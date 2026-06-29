#define _GNU_SOURCE /* accept4 */
#include "fd_grpc_server.h"
#include "fd_grpc_codec.h"
#include "../h2/fd_h2.h"
#include "../h2/fd_h2_rbuf_sock.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Shared reassembly scratch must be >= the HTTP/2 max_frame_size that
   fd_h2_conn_init_server advertises (16384). */
#define FD_GRPC_SERVER_SCRATCH_SZ (16384UL)

#define FD_GRPC_SUBSCRIBE_PATH "/geyser.Geyser/Subscribe"

/* Per-connection state. */

struct fd_grpc_server_conn {
  int   sock;          /* TCP socket, -1 if slot free                */
  uint  used;          /* 1 if slot in use                           */
  uint  got_preface;   /* 1 once the 24B client preface was consumed */

  fd_grpc_server_t * server;
  ulong              conn_id;

  fd_h2_conn_t   conn[1];
  fd_h2_stream_t stream[1];
  fd_h2_tx_op_t  tx_op[1];

  uint  stream_id;       /* active stream id, 0 if none             */
  uint  stream_busy;     /* 1 if the single stream slot is taken    */
  uint  resp_pending;    /* response HEADERS owed to peer           */
  uint  resp_hdrs_sent;  /* response HEADERS already emitted        */
  uint  reject;          /* path not handled -> send UNIMPLEMENTED  */
  uint  tx_active;       /* tx_op currently draining an out span    */
  ulong tx_span;         /* bytes handed to the in-flight tx_op     */

  ulong req_sz;          /* bytes accumulated in req_buf            */

  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_t out[1];   /* outbound framed gRPC messages           */

  uchar * rx_buf;
  uchar * tx_buf;
  uchar * out_buf;
  uchar * req_buf;

  char  path[ 64 ];
  ulong path_len;
};

typedef struct fd_grpc_server_conn fd_grpc_server_conn_t;

struct fd_grpc_server {
  fd_grpc_server_params_t            params;
  fd_grpc_server_callbacks_t const * cb;
  void *                             cb_ctx;

  int listen_sock;

  fd_grpc_server_conn_t * conns;   /* [params.max_conn_cnt] */
  uchar *                 scratch; /* [FD_GRPC_SERVER_SCRATCH_SZ] */
};

/* fd_h2 callback shims -------------------------------------------------*/

static fd_h2_stream_t *
fd_grpc_server_cb_stream_create( fd_h2_conn_t * conn,
                                 uint           stream_id ) {
  (void)stream_id;
  fd_grpc_server_conn_t * c = conn->ctx;
  if( FD_UNLIKELY( c->stream_busy ) ) return NULL; /* one stream per conn */
  fd_h2_stream_init( c->stream );
  c->stream_busy = 1U;
  return c->stream;
}

static fd_h2_stream_t *
fd_grpc_server_cb_stream_query( fd_h2_conn_t * conn,
                                uint           stream_id ) {
  fd_grpc_server_conn_t * c = conn->ctx;
  if( FD_LIKELY( c->stream_busy && c->stream->stream_id==stream_id ) ) return c->stream;
  return NULL;
}

static void
fd_grpc_server_app_stream_close( fd_grpc_server_conn_t * c ) {
  if( FD_UNLIKELY( !c->stream_busy ) ) return;
  fd_grpc_server_t * server = c->server;
  if( server->cb->stream_close ) server->cb->stream_close( server->cb_ctx, c->conn_id );
  c->stream_busy    = 0U;
  c->stream_id      = 0U;
  c->resp_pending   = 0U;
  c->resp_hdrs_sent = 0U;
  c->reject         = 0U;
  c->tx_active      = 0U;
  c->req_sz         = 0UL;
}

static void
fd_grpc_server_cb_rst_stream( fd_h2_conn_t *   conn,
                              fd_h2_stream_t * stream,
                              uint             error_code,
                              int              closed_by ) {
  (void)stream; (void)error_code; (void)closed_by;
  fd_grpc_server_conn_t * c = conn->ctx;
  fd_grpc_server_app_stream_close( c );
}

static void
fd_grpc_server_cb_headers( fd_h2_conn_t *   conn,
                           fd_h2_stream_t * stream,
                           void const *     data,
                           ulong            data_sz,
                           ulong            flags ) {
  fd_grpc_server_conn_t * c = conn->ctx;
  c->stream_id = stream->stream_id;

  /* Decode HPACK header block and capture :path.  Phase 1 assumes the
     header block fits in a single HEADERS frame (END_HEADERS set). */
  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, data, data_sz );
  while( !fd_hpack_rd_done( hpack_rd ) ) {
    uchar scratch_buf[ 1024 ];
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) );
    if( FD_UNLIKELY( err ) ) { fd_h2_conn_error( conn, err ); return; }
    if( hdr->name_len==5UL && fd_memeq( hdr->name, ":path", 5UL ) ) {
      c->path_len = fd_ulong_min( hdr->value_len, sizeof(c->path)-1UL );
      fd_memcpy( c->path, hdr->value, c->path_len );
      c->path[ c->path_len ] = '\0';
    }
  }

  if( flags & FD_H2_FLAG_END_HEADERS ) {
    int path_ok = ( c->path_len==(sizeof(FD_GRPC_SUBSCRIBE_PATH)-1UL) &&
                    fd_memeq( c->path, FD_GRPC_SUBSCRIBE_PATH, sizeof(FD_GRPC_SUBSCRIBE_PATH)-1UL ) );
    c->reject       = !path_ok;
    c->resp_pending = 1U; /* emitted from poll, after SETTINGS */
  }
}

static void
fd_grpc_server_cb_data( fd_h2_conn_t *   conn,
                        fd_h2_stream_t * stream,
                        void const *     data,
                        ulong            data_sz,
                        ulong            flags ) {
  (void)stream; (void)flags;
  fd_grpc_server_conn_t * c      = conn->ctx;
  fd_grpc_server_t *      server = c->server;
  if( FD_UNLIKELY( c->reject ) ) return;

  /* Append to request reassembly buffer (bounded). */
  ulong cap = server->params.max_request_sz;
  if( FD_UNLIKELY( c->req_sz + data_sz > cap ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
    return;
  }
  fd_memcpy( c->req_buf + c->req_sz, data, data_sz );
  c->req_sz += data_sz;

  /* Extract any complete gRPC length-prefixed messages. */
  for(;;) {
    if( c->req_sz < 5UL ) break;
    uchar const * h = c->req_buf;
    ulong msg_sz = ( (ulong)h[1]<<24 ) | ( (ulong)h[2]<<16 ) | ( (ulong)h[3]<<8 ) | (ulong)h[4];
    if( FD_UNLIKELY( 5UL+msg_sz > cap ) ) { fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL ); return; }
    if( c->req_sz < 5UL+msg_sz ) break;
    if( server->cb->request_msg ) {
      server->cb->request_msg( server->cb_ctx, c->conn_id, c->path, c->path_len, c->req_buf+5UL, msg_sz );
    }
    ulong consumed = 5UL+msg_sz;
    ulong rem = c->req_sz - consumed;
    if( rem ) memmove( c->req_buf, c->req_buf+consumed, rem );
    c->req_sz = rem;
  }
}

static fd_h2_callbacks_t const fd_grpc_server_h2_cb = {
  .stream_create        = fd_grpc_server_cb_stream_create,
  .stream_query         = fd_grpc_server_cb_stream_query,
  .conn_established     = fd_h2_noop_conn_established,
  .conn_final           = fd_h2_noop_conn_final,
  .headers              = fd_grpc_server_cb_headers,
  .data                 = fd_grpc_server_cb_data,
  .rst_stream           = fd_grpc_server_cb_rst_stream,
  .window_update        = fd_h2_noop_window_update,
  .stream_window_update = fd_h2_noop_stream_window_update,
  .ping_ack             = fd_h2_noop_ping_ack,
};

/* Layout ---------------------------------------------------------------*/

ulong
fd_grpc_server_align( void ) {
  return 128UL;
}

ulong
fd_grpc_server_footprint( fd_grpc_server_params_t params ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_grpc_server_align(),       sizeof(fd_grpc_server_t)                               );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_conn_t), params.max_conn_cnt*sizeof(fd_grpc_server_conn_t)    );
  l = FD_LAYOUT_APPEND( l, 16UL,                         FD_GRPC_SERVER_SCRATCH_SZ                              );
  for( ulong i=0UL; i<params.max_conn_cnt; i++ ) {
    l = FD_LAYOUT_APPEND( l, 16UL, params.conn_rx_buf_sz  );
    l = FD_LAYOUT_APPEND( l, 16UL, params.conn_tx_buf_sz  );
    l = FD_LAYOUT_APPEND( l, 16UL, params.conn_out_buf_sz );
    l = FD_LAYOUT_APPEND( l, 16UL, params.max_request_sz  );
  }
  return FD_LAYOUT_FINI( l, fd_grpc_server_align() );
}

void *
fd_grpc_server_new( void *                             mem,
                    fd_grpc_server_params_t            params,
                    fd_grpc_server_callbacks_t const * callbacks,
                    void *                             ctx ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !params.max_conn_cnt ) ) { FD_LOG_WARNING(( "zero max_conn_cnt" )); return NULL; }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_grpc_server_t * server = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_server_align(),         sizeof(fd_grpc_server_t)                            );
  fd_grpc_server_conn_t * conns = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_conn_t), params.max_conn_cnt*sizeof(fd_grpc_server_conn_t) );
  uchar * scratch = FD_SCRATCH_ALLOC_APPEND( l, 16UL, FD_GRPC_SERVER_SCRATCH_SZ );

  fd_memset( server, 0, sizeof(fd_grpc_server_t) );
  fd_memset( conns,  0, params.max_conn_cnt*sizeof(fd_grpc_server_conn_t) );

  server->params      = params;
  server->cb          = callbacks;
  server->cb_ctx      = ctx;
  server->listen_sock = -1;
  server->conns       = conns;
  server->scratch     = scratch;

  for( ulong i=0UL; i<params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t * c = &conns[ i ];
    c->sock    = -1;
    c->server  = server;
    c->conn_id = i;
    c->rx_buf  = FD_SCRATCH_ALLOC_APPEND( l, 16UL, params.conn_rx_buf_sz  );
    c->tx_buf  = FD_SCRATCH_ALLOC_APPEND( l, 16UL, params.conn_tx_buf_sz  );
    c->out_buf = FD_SCRATCH_ALLOC_APPEND( l, 16UL, params.conn_out_buf_sz );
    c->req_buf = FD_SCRATCH_ALLOC_APPEND( l, 16UL, params.max_request_sz  );
  }

  return server;
}

fd_grpc_server_t *
fd_grpc_server_join( void * mem ) {
  return (fd_grpc_server_t *)mem;
}

/* Connection lifecycle -------------------------------------------------*/

static void
fd_grpc_server_conn_reset( fd_grpc_server_conn_t * c ) {
  fd_grpc_server_t * server = c->server;
  ulong              conn_id = c->conn_id;
  uchar * rx_buf  = c->rx_buf;
  uchar * tx_buf  = c->tx_buf;
  uchar * out_buf = c->out_buf;
  uchar * req_buf = c->req_buf;

  fd_memset( c, 0, sizeof(fd_grpc_server_conn_t) );
  c->sock    = -1;
  c->server  = server;
  c->conn_id = conn_id;
  c->rx_buf  = rx_buf;
  c->tx_buf  = tx_buf;
  c->out_buf = out_buf;
  c->req_buf = req_buf;
}

void
fd_grpc_server_close( fd_grpc_server_t * server,
                      ulong              conn_id ) {
  if( FD_UNLIKELY( conn_id>=server->params.max_conn_cnt ) ) return;
  fd_grpc_server_conn_t * c = &server->conns[ conn_id ];
  if( FD_UNLIKELY( !c->used ) ) return;
  fd_grpc_server_app_stream_close( c );
  if( c->sock>=0 ) close( c->sock );
  fd_grpc_server_conn_reset( c );
}

static int
fd_grpc_server_accept( fd_grpc_server_t * server ) {
  int accepted = 0;
  for(;;) {
    int s = accept4( server->listen_sock, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK );
    if( s<0 ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) break;
      if( errno==EINTR ) continue;
      break;
    }

    /* Find a free conn slot. */
    fd_grpc_server_conn_t * c = NULL;
    for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
      if( !server->conns[ i ].used ) { c = &server->conns[ i ]; break; }
    }
    if( FD_UNLIKELY( !c ) ) { close( s ); continue; } /* at capacity */

    fd_grpc_server_conn_reset( c );
    c->sock        = s;
    c->used        = 1U;
    c->got_preface = 0U;
    fd_h2_rbuf_init( c->rbuf_rx, c->rx_buf,  server->params.conn_rx_buf_sz  );
    fd_h2_rbuf_init( c->rbuf_tx, c->tx_buf,  server->params.conn_tx_buf_sz  );
    fd_h2_rbuf_init( c->out,     c->out_buf, server->params.conn_out_buf_sz );
    accepted = 1;
  }
  return accepted;
}

/* Outbound response headers --------------------------------------------*/

static void
fd_grpc_server_send_resp_hdrs( fd_grpc_server_conn_t * c ) {
  /* :status: 200  -> 0x88 (static index 8)
     content-type: application/grpc+proto -> literal w/ indexed name 31 */
  static uchar const hpack[] = {
    0x88,
    0x5f, 0x16, 'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c','+','p','r','o','t','o'
  };
  fd_h2_tx( c->rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, c->stream_id );
}

static void
fd_grpc_server_send_unimplemented( fd_grpc_server_conn_t * c ) {
  /* Trailers-only response: :status 200, content-type, grpc-status: 12. */
  static uchar const hpack[] = {
    0x88,
    0x5f, 0x16, 'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c','+','p','r','o','t','o',
    0x00, 0x0b, 'g','r','p','c','-','s','t','a','t','u','s', 0x02, '1','2'
  };
  fd_h2_tx( c->rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS,
            (uint)(FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM), c->stream_id );
}

/* Drain queued outbound gRPC messages into the HTTP/2 stream, honoring
   flow control. */

static void
fd_grpc_server_flush_out( fd_grpc_server_conn_t * c ) {
  if( FD_UNLIKELY( !c->stream_busy || !c->resp_hdrs_sent ) ) return;

  for( int iter=0; iter<8; iter++ ) {
    if( !c->tx_active ) {
      ulong sz=0UL, split_sz=0UL;
      uchar * p = fd_h2_rbuf_peek_used( c->out, &sz, &split_sz );
      if( !sz ) return;
      fd_h2_tx_op_init( c->tx_op, p, sz, 0U );
      c->tx_active = 1U;
      c->tx_span   = sz;
    }
    fd_h2_tx_op_copy( c->conn, c->stream, c->rbuf_tx, c->tx_op );
    if( c->tx_op->chunk_sz==0UL ) {
      fd_h2_rbuf_skip( c->out, c->tx_span );
      c->tx_active = 0U;
    } else {
      return; /* blocked on flow control / tx buffer */
    }
  }
}

/* Service one connection (non-blocking single pass). */

static int
fd_grpc_server_service_conn( fd_grpc_server_t *      server,
                             fd_grpc_server_conn_t * c ) {
  int busy = 0;

  /* 1. Read whatever is available. */
  int rx_err = fd_h2_rbuf_recvmsg( c->rbuf_rx, c->sock, MSG_NOSIGNAL );
  if( FD_UNLIKELY( rx_err==EPIPE ) ) { fd_grpc_server_close( server, c->conn_id ); return 1; }
  if( FD_UNLIKELY( rx_err && rx_err!=EAGAIN ) ) { fd_grpc_server_close( server, c->conn_id ); return 1; }
  if( fd_h2_rbuf_used_sz( c->rbuf_rx ) ) busy = 1;

  /* 2. Consume the client preface, then bootstrap the server conn. */
  if( FD_UNLIKELY( !c->got_preface ) ) {
    if( fd_h2_rbuf_used_sz( c->rbuf_rx ) < 24UL ) return busy;
    uchar tmp[ 24 ];
    fd_h2_rbuf_pop_copy( c->rbuf_rx, tmp, 24UL );
    if( FD_UNLIKELY( !fd_memeq( tmp, fd_h2_client_preface, 24UL ) ) ) {
      fd_grpc_server_close( server, c->conn_id );
      return 1;
    }
    fd_h2_conn_init_server( c->conn );
    c->conn->ctx = c;
    c->conn->self_settings.max_concurrent_streams = 1U;
    c->got_preface = 1U;
  }

  /* 3. Emit pending control frames (server SETTINGS on the first pass,
        plus any ACKs/WINDOW_UPDATEs queued by the previous rx). */
  fd_h2_tx_control( c->conn, c->rbuf_tx, &fd_grpc_server_h2_cb );

  /* 4. Emit deferred response headers (after SETTINGS). */
  if( c->resp_pending && fd_h2_rbuf_free_sz( c->rbuf_tx )>=128UL ) {
    if( c->reject ) {
      fd_grpc_server_send_unimplemented( c );
      c->resp_pending = 0U;
      fd_h2_stream_close_tx( c->stream, c->conn );
      fd_grpc_server_app_stream_close( c );
    } else {
      fd_grpc_server_send_resp_hdrs( c );
      c->resp_pending   = 0U;
      c->resp_hdrs_sent = 1U;
    }
  }

  /* 5. Drain queued response messages. */
  fd_grpc_server_flush_out( c );

  /* 6. Flush the transmit buffer (best-effort, non-blocking). */
  if( fd_h2_rbuf_used_sz( c->rbuf_tx ) ) {
    int tx_err = fd_h2_rbuf_sendmsg( c->rbuf_tx, c->sock, MSG_NOSIGNAL );
    if( FD_UNLIKELY( tx_err && tx_err!=EAGAIN ) ) { fd_grpc_server_close( server, c->conn_id ); return 1; }
    busy = 1;
  }

  if( FD_UNLIKELY( c->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
    fd_grpc_server_close( server, c->conn_id );
    return 1;
  }

  /* 7. Process inbound frames (fires callbacks, queues control for next
        pass). */
  if( fd_h2_rbuf_used_sz( c->rbuf_rx ) ) {
    fd_h2_rx( c->conn, c->rbuf_rx, c->rbuf_tx, server->scratch, FD_GRPC_SERVER_SCRATCH_SZ, &fd_grpc_server_h2_cb );
    busy = 1;
  }

  if( FD_UNLIKELY( c->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
    fd_grpc_server_close( server, c->conn_id );
    return 1;
  }

  return busy;
}

/* Public API -----------------------------------------------------------*/

int
fd_grpc_server_listen( fd_grpc_server_t * server,
                       uint               listen_addr,
                       ushort             listen_port ) {
  int s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  if( FD_UNLIKELY( s<0 ) ) return -errno;

  int one = 1;
  setsockopt( s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int) );

  int fl = fcntl( s, F_GETFL, 0 );
  if( fl<0 || fcntl( s, F_SETFL, fl|O_NONBLOCK )<0 ) { int e=errno; close( s ); return -e; }

  struct sockaddr_in addr = {0};
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = listen_addr; /* already network order */
  addr.sin_port        = fd_ushort_bswap( listen_port );
  if( FD_UNLIKELY( bind( s, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) )<0 ) ) {
    int e=errno; close( s ); return -e;
  }
  if( FD_UNLIKELY( listen( s, 16 )<0 ) ) { int e=errno; close( s ); return -e; }

  server->listen_sock = s;
  return s;
}

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int *              charge_busy ) {
  int busy = 0;
  if( FD_LIKELY( server->listen_sock>=0 ) ) busy |= fd_grpc_server_accept( server );

  int serviced = 0;
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t * c = &server->conns[ i ];
    if( !c->used ) continue;
    serviced++;
    busy |= fd_grpc_server_service_conn( server, c );
  }

  if( busy && charge_busy ) *charge_busy = 1;
  return serviced;
}

int
fd_grpc_server_has_stream( fd_grpc_server_t const * server,
                           ulong                    conn_id ) {
  if( FD_UNLIKELY( conn_id>=server->params.max_conn_cnt ) ) return 0;
  fd_grpc_server_conn_t const * c = &server->conns[ conn_id ];
  return c->used && c->stream_busy && c->resp_hdrs_sent && !c->reject;
}

int
fd_grpc_server_publish( fd_grpc_server_t * server,
                        ulong              conn_id,
                        uchar const *      msg,
                        ulong              msg_sz ) {
  if( FD_UNLIKELY( !fd_grpc_server_has_stream( server, conn_id ) ) ) return 0;
  fd_grpc_server_conn_t * c = &server->conns[ conn_id ];

  ulong need = 5UL + msg_sz;
  if( FD_UNLIKELY( msg_sz>UINT_MAX || fd_h2_rbuf_free_sz( c->out )<need ) ) return 0;

  uchar hdr[5];
  hdr[0] = 0; /* not compressed */
  hdr[1] = (uchar)( msg_sz>>24 );
  hdr[2] = (uchar)( msg_sz>>16 );
  hdr[3] = (uchar)( msg_sz>> 8 );
  hdr[4] = (uchar)( msg_sz     );
  fd_h2_rbuf_push( c->out, hdr, 5UL    );
  fd_h2_rbuf_push( c->out, msg, msg_sz );
  return 1;
}

ulong
fd_grpc_server_max_conn_cnt( fd_grpc_server_t const * server ) {
  return server->params.max_conn_cnt;
}

int
fd_grpc_server_listen_fd( fd_grpc_server_t const * server ) {
  return server->listen_sock;
}
