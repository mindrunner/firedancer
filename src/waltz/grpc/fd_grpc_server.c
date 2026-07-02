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

#define FD_GRPC_SUBSCRIBE_PATH  "/geyser.Geyser/Subscribe"
#define FD_GRPC_GETVERSION_PATH "/geyser.Geyser/GetVersion"

/* GetVersionResponse.version string (Yellowstone convention is a JSON
   blob; clients read it as an opaque string). */
#define FD_GRPC_SERVER_VERSION "{\"version\":\"0.1.0\",\"package\":\"firedancer-geyser\",\"proto\":\"1.0.0\"}"

/* Per-connection state. */

/* Max concurrent HTTP/2 streams per connection.  Proxies such as Envoy
   multiplex many client requests (unary GetVersion probes + a Subscribe)
   onto one pooled upstream connection, so the server must accept several
   streams at once rather than one. */
#define FD_GRPC_SERVER_MAX_STREAMS (16U)

/* Stream kinds. */
#define FD_GRPC_SK_NONE       (0U)
#define FD_GRPC_SK_SUBSCRIBE  (1U)
#define FD_GRPC_SK_GETVERSION (2U)
#define FD_GRPC_SK_REJECT     (3U)

/* Per-stream state.  h2 MUST be the first member so a fd_h2_stream_t*
   from a callback can be cast back to the enclosing struct. */
struct fd_grpc_server_stream {
  fd_h2_stream_t h2[1];
  uint  used;
  uint  id;
  uint  kind;           /* FD_GRPC_SK_*                            */
  uint  resp_pending;   /* response owed to peer                   */
  uint  resp_hdrs_sent; /* streaming response HEADERS emitted      */
  char  path[ 64 ];
  ulong path_len;
};

typedef struct fd_grpc_server_stream fd_grpc_server_stream_t;

struct fd_grpc_server_conn {
  int   sock;          /* TCP socket, -1 if slot free                */
  uint  used;          /* 1 if slot in use                           */
  uint  got_preface;   /* 1 once the 24B client preface was consumed */

  fd_grpc_server_t * server;
  ulong              conn_id;

  fd_h2_conn_t   conn[1];
  fd_grpc_server_stream_t streams[ FD_GRPC_SERVER_MAX_STREAMS ];

  fd_h2_tx_op_t  tx_op[1];
  uint  tx_active;       /* tx_op currently draining an out span    */
  ulong tx_span;         /* bytes handed to the in-flight tx_op     */

  /* The single long-lived Subscribe stream owns the out ring and the
     request reassembly buffer.  <0 when there is no active subscription. */
  long  sub_slot;
  ulong req_sz;          /* bytes accumulated in req_buf (subscribe) */

  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_t out[1];   /* outbound framed gRPC messages (subscribe) */

  uchar * rx_buf;
  uchar * tx_buf;
  uchar * out_buf;
  uchar * req_buf;
};

typedef struct fd_grpc_server_conn fd_grpc_server_conn_t;

/* Recover the enclosing per-stream struct from a fd_h2_stream_t*. */
static inline fd_grpc_server_stream_t *
fd_grpc_server_stream_of( fd_h2_stream_t * h2 ) {
  return (fd_grpc_server_stream_t *)h2; /* h2 is the first member */
}

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
  fd_grpc_server_conn_t * c = conn->ctx;
  for( uint i=0U; i<FD_GRPC_SERVER_MAX_STREAMS; i++ ) {
    fd_grpc_server_stream_t * s = &c->streams[ i ];
    if( !s->used ) {
      fd_h2_stream_init( s->h2 );
      s->used          = 1U;
      s->id            = stream_id;
      s->kind          = FD_GRPC_SK_NONE;
      s->resp_pending  = 0U;
      s->resp_hdrs_sent= 0U;
      s->path_len      = 0UL;
      return s->h2;
    }
  }
  return NULL; /* at capacity -> REFUSED_STREAM */
}

static fd_h2_stream_t *
fd_grpc_server_cb_stream_query( fd_h2_conn_t * conn,
                                uint           stream_id ) {
  fd_grpc_server_conn_t * c = conn->ctx;
  for( uint i=0U; i<FD_GRPC_SERVER_MAX_STREAMS; i++ ) {
    fd_grpc_server_stream_t * s = &c->streams[ i ];
    if( s->used && s->id==stream_id ) return s->h2;
  }
  return NULL;
}

/* Free a per-stream slot.  If it was the connection's Subscribe stream,
   tear down the subscription (upcall + reset the out ring). */
static void
fd_grpc_server_stream_free( fd_grpc_server_conn_t *   c,
                            fd_grpc_server_stream_t * s ) {
  if( FD_UNLIKELY( !s->used ) ) return;
  if( (long)( s - c->streams )==c->sub_slot ) {
    fd_grpc_server_t * server = c->server;
    if( server->cb->stream_close ) server->cb->stream_close( server->cb_ctx, c->conn_id );
    c->sub_slot  = -1L;
    c->req_sz    = 0UL;
    c->tx_active = 0U;
    fd_h2_rbuf_init( c->out, c->out_buf, server->params.conn_out_buf_sz );
  }
  s->used           = 0U;
  s->kind           = FD_GRPC_SK_NONE;
  s->resp_pending   = 0U;
  s->resp_hdrs_sent = 0U;
}

static void
fd_grpc_server_cb_rst_stream( fd_h2_conn_t *   conn,
                              fd_h2_stream_t * stream,
                              uint             error_code,
                              int              closed_by ) {
  (void)error_code; (void)closed_by;
  fd_grpc_server_conn_t * c = conn->ctx;
  fd_grpc_server_stream_free( c, fd_grpc_server_stream_of( stream ) );
}

static void
fd_grpc_server_cb_headers( fd_h2_conn_t *   conn,
                           fd_h2_stream_t * stream,
                           void const *     data,
                           ulong            data_sz,
                           ulong            flags ) {
  fd_grpc_server_conn_t *   c = conn->ctx;
  fd_grpc_server_stream_t * s = fd_grpc_server_stream_of( stream );

  /* Decode HPACK header block and capture :path.  Assumes the header
     block fits in a single HEADERS frame (END_HEADERS set). */
  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, data, data_sz );
  while( !fd_hpack_rd_done( hpack_rd ) ) {
    uchar scratch_buf[ 1024 ];
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) );
    if( FD_UNLIKELY( err ) ) { fd_h2_conn_error( conn, err ); return; }
    if( hdr->name_len==5UL && fd_memeq( hdr->name, ":path", 5UL ) ) {
      s->path_len = fd_ulong_min( hdr->value_len, sizeof(s->path)-1UL );
      fd_memcpy( s->path, hdr->value, s->path_len );
      s->path[ s->path_len ] = '\0';
    }
  }

  if( flags & FD_H2_FLAG_END_HEADERS ) {
    int is_sub = ( s->path_len==(sizeof(FD_GRPC_SUBSCRIBE_PATH)-1UL) &&
                   fd_memeq( s->path, FD_GRPC_SUBSCRIBE_PATH, sizeof(FD_GRPC_SUBSCRIBE_PATH)-1UL ) );
    int is_ver = ( s->path_len==(sizeof(FD_GRPC_GETVERSION_PATH)-1UL) &&
                   fd_memeq( s->path, FD_GRPC_GETVERSION_PATH, sizeof(FD_GRPC_GETVERSION_PATH)-1UL ) );
    if( is_sub ) {
      s->kind        = FD_GRPC_SK_SUBSCRIBE;
      c->sub_slot    = (long)( s - c->streams );
      c->req_sz      = 0UL;
      s->resp_pending= 1U; /* respond with HEADERS now; keep stream open */
    } else {
      s->kind = is_ver ? FD_GRPC_SK_GETVERSION : FD_GRPC_SK_REJECT;
      /* Unary: respond only once the client has finished sending, so we
         never free the stream while more request frames are inbound. */
      if( flags & FD_H2_FLAG_END_STREAM ) s->resp_pending = 1U;
    }
  }
}

static void
fd_grpc_server_cb_data( fd_h2_conn_t *   conn,
                        fd_h2_stream_t * stream,
                        void const *     data,
                        ulong            data_sz,
                        ulong            flags ) {
  fd_grpc_server_conn_t *   c      = conn->ctx;
  fd_grpc_server_t *        server = c->server;
  fd_grpc_server_stream_t * s      = fd_grpc_server_stream_of( stream );

  if( s->kind!=FD_GRPC_SK_SUBSCRIBE ) {
    /* Unary request body is ignored; respond once fully received. */
    if( flags & FD_H2_FLAG_END_STREAM ) s->resp_pending = 1U;
    return;
  }

  /* Subscribe: accumulate into the per-conn request buffer. */
  ulong cap = server->params.max_request_sz;
  if( FD_UNLIKELY( c->req_sz + data_sz > cap ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL );
    return;
  }
  fd_memcpy( c->req_buf + c->req_sz, data, data_sz );
  c->req_sz += data_sz;

  for(;;) {
    if( c->req_sz < 5UL ) break;
    uchar const * h = c->req_buf;
    ulong msg_sz = ( (ulong)h[1]<<24 ) | ( (ulong)h[2]<<16 ) | ( (ulong)h[3]<<8 ) | (ulong)h[4];
    if( FD_UNLIKELY( 5UL+msg_sz > cap ) ) { fd_h2_conn_error( conn, FD_H2_ERR_FLOW_CONTROL ); return; }
    if( c->req_sz < 5UL+msg_sz ) break;
    if( server->cb->request_msg ) {
      server->cb->request_msg( server->cb_ctx, c->conn_id, s->path, s->path_len, c->req_buf+5UL, msg_sz );
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
  c->sock     = -1;
  c->server   = server;
  c->conn_id  = conn_id;
  c->sub_slot = -1L;
  c->rx_buf   = rx_buf;
  c->tx_buf   = tx_buf;
  c->out_buf  = out_buf;
  c->req_buf  = req_buf;
}

void
fd_grpc_server_close( fd_grpc_server_t * server,
                      ulong              conn_id ) {
  if( FD_UNLIKELY( conn_id>=server->params.max_conn_cnt ) ) return;
  fd_grpc_server_conn_t * c = &server->conns[ conn_id ];
  if( FD_UNLIKELY( !c->used ) ) return;
  if( c->sub_slot>=0L && server->cb->stream_close ) server->cb->stream_close( server->cb_ctx, c->conn_id );
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
    if( FD_UNLIKELY( !c ) ) { /* at capacity */
      FD_LOG_WARNING(( "geyser: dropping new connection, at capacity (%lu conns)", server->params.max_conn_cnt ));
      close( s );
      continue;
    }

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
fd_grpc_server_send_resp_hdrs( fd_grpc_server_conn_t * c,
                               uint                    stream_id ) {
  /* :status: 200  -> 0x88 (static index 8)
     content-type: application/grpc+proto -> literal w/ indexed name 31 */
  static uchar const hpack[] = {
    0x88,
    0x5f, 0x16, 'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c','+','p','r','o','t','o'
  };
  fd_h2_tx( c->rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );
}

static void
fd_grpc_server_send_unimplemented( fd_grpc_server_conn_t * c,
                                   uint                    stream_id ) {
  /* Trailers-only response: :status 200, content-type, grpc-status: 12. */
  static uchar const hpack[] = {
    0x88,
    0x5f, 0x16, 'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c','+','p','r','o','t','o',
    0x00, 0x0b, 'g','r','p','c','-','s','t','a','t','u','s', 0x02, '1','2'
  };
  fd_h2_tx( c->rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS,
            (uint)(FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM), stream_id );
}

/* Emit a complete unary GetVersion response: HEADERS + one DATA message
   (GetVersionResponse) + grpc-status:0 trailers.  Caller ensures rbuf_tx
   has space. */

static void
fd_grpc_server_send_getversion( fd_grpc_server_conn_t * c,
                                uint                    stream_id ) {
  static uchar const resp_hdrs[] = {
    0x88,
    0x5f, 0x16, 'a','p','p','l','i','c','a','t','i','o','n','/','g','r','p','c','+','p','r','o','t','o'
  };
  fd_h2_tx( c->rbuf_tx, resp_hdrs, sizeof(resp_hdrs), FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );

  /* GetVersionResponse { string version = 1 }, gRPC length-prefixed. */
  static char const ver[]  = FD_GRPC_SERVER_VERSION;
  ulong             verlen = sizeof(ver)-1UL; /* < 128 */
  uchar msg[ 5 + 2 + sizeof(ver) ];
  ulong pb = 0UL;
  msg[ 5+pb++ ] = 0x0a;             /* field 1, wire type 2 (LEN) */
  msg[ 5+pb++ ] = (uchar)verlen;    /* single-byte varint length */
  fd_memcpy( msg+5+pb, ver, verlen ); pb += verlen;
  msg[0] = 0;                       /* uncompressed */
  msg[1] = (uchar)( pb>>24 );
  msg[2] = (uchar)( pb>>16 );
  msg[3] = (uchar)( pb>> 8 );
  msg[4] = (uchar)( pb     );
  fd_h2_tx( c->rbuf_tx, msg, 5UL+pb, FD_H2_FRAME_TYPE_DATA, 0U, stream_id );

  /* trailers: grpc-status: 0, END_STREAM */
  static uchar const trailers[] = {
    0x00, 0x0b, 'g','r','p','c','-','s','t','a','t','u','s', 0x01, '0'
  };
  fd_h2_tx( c->rbuf_tx, trailers, sizeof(trailers), FD_H2_FRAME_TYPE_HEADERS,
            (uint)(FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM), stream_id );
}

/* Drain queued outbound gRPC messages into the Subscribe stream, honoring
   flow control. */

static void
fd_grpc_server_flush_out( fd_grpc_server_conn_t * c ) {
  if( FD_UNLIKELY( c->sub_slot<0L ) ) return;
  fd_grpc_server_stream_t * s = &c->streams[ c->sub_slot ];
  if( FD_UNLIKELY( !s->used || !s->resp_hdrs_sent ) ) return;

  for( int iter=0; iter<8; iter++ ) {
    if( !c->tx_active ) {
      ulong sz=0UL, split_sz=0UL;
      uchar * p = fd_h2_rbuf_peek_used( c->out, &sz, &split_sz );
      if( !sz ) return;
      fd_h2_tx_op_init( c->tx_op, p, sz, 0U );
      c->tx_active = 1U;
      c->tx_span   = sz;
    }
    fd_h2_tx_op_copy( c->conn, s->h2, c->rbuf_tx, c->tx_op );
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
    c->conn->self_settings.max_concurrent_streams = FD_GRPC_SERVER_MAX_STREAMS;
    c->got_preface = 1U;
  }

  /* 3. Emit pending control frames (server SETTINGS on the first pass,
        plus any ACKs/WINDOW_UPDATEs queued by the previous rx). */
  fd_h2_tx_control( c->conn, c->rbuf_tx, &fd_grpc_server_h2_cb );

  /* 4. Emit deferred responses (after SETTINGS).  Unary responses are
        complete + fully close/free the stream (the client already sent
        END_STREAM, so no late frames can hit the freed slot).  Subscribe
        sends HEADERS and stays open. */
  for( uint i=0U; i<FD_GRPC_SERVER_MAX_STREAMS; i++ ) {
    fd_grpc_server_stream_t * s = &c->streams[ i ];
    if( !s->used || !s->resp_pending ) continue;
    if( fd_h2_rbuf_free_sz( c->rbuf_tx )<512UL ) break; /* retry next pass */

    if( s->kind==FD_GRPC_SK_REJECT ) {
      fd_grpc_server_send_unimplemented( c, s->id );
      s->resp_pending = 0U;
      fd_h2_stream_reset( s->h2, c->conn );
      fd_grpc_server_stream_free( c, s );
    } else if( s->kind==FD_GRPC_SK_GETVERSION ) {
      fd_grpc_server_send_getversion( c, s->id );
      s->resp_pending = 0U;
      fd_h2_stream_reset( s->h2, c->conn );
      fd_grpc_server_stream_free( c, s );
    } else { /* subscribe */
      fd_grpc_server_send_resp_hdrs( c, s->id );
      s->resp_pending   = 0U;
      s->resp_hdrs_sent = 1U;
    }
  }

  /* 5. Drain queued response messages. */
  fd_grpc_server_flush_out( c );

  /* 6. Flush the transmit buffer (best-effort, non-blocking). */
  if( fd_h2_rbuf_used_sz( c->rbuf_tx ) ) {
    int tx_err = fd_h2_rbuf_sendmsg( c->rbuf_tx, c->sock, MSG_NOSIGNAL );
    if( FD_UNLIKELY( tx_err && tx_err!=EAGAIN ) ) {
      FD_LOG_WARNING(( "geyser: conn %lu sendmsg failed (%i-%s)", c->conn_id, tx_err, fd_io_strerror( tx_err ) ));
      fd_grpc_server_close( server, c->conn_id );
      return 1;
    }
    busy = 1;
  }

  if( FD_UNLIKELY( c->conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
    FD_LOG_WARNING(( "geyser: conn %lu h2 GOAWAY (err=%u-%s) [tx path]", c->conn_id,
                     (uint)c->conn->conn_error, fd_h2_strerror( (uint)c->conn->conn_error ) ));
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
    FD_LOG_WARNING(( "geyser: conn %lu h2 GOAWAY (err=%u-%s) [rx path]", c->conn_id,
                     (uint)c->conn->conn_error, fd_h2_strerror( (uint)c->conn->conn_error ) ));
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
  if( !c->used || c->sub_slot<0L ) return 0;
  fd_grpc_server_stream_t const * s = &c->streams[ c->sub_slot ];
  return s->used && s->resp_hdrs_sent;
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
