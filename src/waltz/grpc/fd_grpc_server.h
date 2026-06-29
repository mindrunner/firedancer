#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_server_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_server_h

/* fd_grpc_server.h provides a minimal server-side gRPC-over-HTTP/2
   endpoint.  It is the server counterpart to fd_grpc_client.c and is
   built from the same fd_h2 framing layer (fd_h2_conn_init_server) and
   gRPC codec primitives.

   The server is single threaded and non-blocking.  It is designed to be
   driven from a Firedancer tile's before_credit handler, in the same
   way fd_http_server is driven by the rpc/gui tiles: the tile calls
   fd_grpc_server_poll() periodically, which accepts new TCP connections,
   services HTTP/2 frames, and flushes queued response messages while
   respecting HTTP/2 flow control.

   This v1 implementation targets server-streaming RPCs (one request
   message followed by an open-ended stream of response messages), which
   is what the Yellowstone Geyser `Subscribe` method needs.  Each
   connection carries at most one concurrent stream.

   Transport security (TLS) and authentication are out of scope here and
   are layered in by the caller in a later phase. */

#include "../h2/fd_h2_base.h"

/* fd_grpc_server_params_t configures sizing of a server instance. */

struct fd_grpc_server_params {
  ulong max_conn_cnt;     /* max concurrent TCP connections          */
  ulong conn_rx_buf_sz;   /* per-conn HTTP/2 receive ring size       */
  ulong conn_tx_buf_sz;   /* per-conn HTTP/2 transmit ring size      */
  ulong conn_out_buf_sz;  /* per-conn outbound gRPC message ring     */
  ulong max_request_sz;   /* max size of a single inbound gRPC msg   */
};

typedef struct fd_grpc_server_params fd_grpc_server_params_t;

/* fd_grpc_server_callbacks_t is the upcall vtable into the application
   (e.g. the geyser tile).  ctx is the opaque pointer passed to
   fd_grpc_server_new. */

struct fd_grpc_server_callbacks {

  /* request_msg is invoked when a complete gRPC request message has been
     received on a stream.  path/path_len name the RPC method (e.g.
     "/geyser.Geyser/Subscribe").  msg/msg_sz is the de-framed protobuf
     request payload (the 5 byte gRPC length prefix has been stripped).
     For server-streaming RPCs this is typically called once per stream,
     but the peer may send additional request messages to update the
     subscription. */

  void (* request_msg)( void *        ctx,
                        ulong         conn_id,
                        char const *  path,
                        ulong         path_len,
                        uchar const * msg,
                        ulong         msg_sz );

  /* stream_close is invoked when a stream (or its connection) is torn
     down.  The application must drop any per-conn_id state. */

  void (* stream_close)( void * ctx,
                         ulong  conn_id );

};

typedef struct fd_grpc_server_callbacks fd_grpc_server_callbacks_t;

struct fd_grpc_server;
typedef struct fd_grpc_server fd_grpc_server_t;

FD_PROTOTYPES_BEGIN

ulong
fd_grpc_server_align( void );

ulong
fd_grpc_server_footprint( fd_grpc_server_params_t params );

void *
fd_grpc_server_new( void *                             mem,
                    fd_grpc_server_params_t            params,
                    fd_grpc_server_callbacks_t const * callbacks,
                    void *                             ctx );

fd_grpc_server_t *
fd_grpc_server_join( void * mem );

/* fd_grpc_server_listen opens a non-blocking listening TCP socket bound
   to (listen_addr, listen_port).  listen_addr is a big-endian IPv4
   address (network order, as produced by fd_cstr_to_ip4_addr).  Returns
   the listen socket fd on success (>=0), or a negative errno on
   failure. */

int
fd_grpc_server_listen( fd_grpc_server_t * server,
                       uint               listen_addr,
                       ushort             listen_port );

/* fd_grpc_server_poll performs one non-blocking service pass: accept new
   connections, read/process inbound frames, and flush queued responses.
   Sets *charge_busy to 1 if any work was performed.  Returns the number
   of connections serviced. */

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int *              charge_busy );

/* fd_grpc_server_has_stream returns 1 if conn_id currently has an open
   server-streaming response stream that the application may publish to. */

int
fd_grpc_server_has_stream( fd_grpc_server_t const * server,
                           ulong                    conn_id );

/* fd_grpc_server_publish enqueues one gRPC response message on conn_id's
   stream.  msg/msg_sz is a serialized protobuf message; the server adds
   the 5 byte gRPC length prefix.  Returns 1 on success, 0 if there is no
   open stream or the outbound buffer is full (the caller may then choose
   to evict the connection via fd_grpc_server_close). */

int
fd_grpc_server_publish( fd_grpc_server_t * server,
                        ulong              conn_id,
                        uchar const *      msg,
                        ulong              msg_sz );

/* fd_grpc_server_close tears down conn_id (e.g. a slow consumer). */

void
fd_grpc_server_close( fd_grpc_server_t * server,
                      ulong              conn_id );

/* fd_grpc_server_max_conn_cnt returns the configured connection cap, so
   the application can size per-conn_id state. */

ulong
fd_grpc_server_max_conn_cnt( fd_grpc_server_t const * server );

/* fd_grpc_server_listen_fd / conn_fd expose file descriptors for seccomp
   fd allow-listing and io_uring/poll integration. */

int
fd_grpc_server_listen_fd( fd_grpc_server_t const * server );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_server_h */
