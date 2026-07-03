/* test_grpc_server is a standalone harness for fd_grpc_server.  It
   serves the same two RPCs the geyser tile registers (a streaming
   "Subscribe" and a unary "GetVersion") on a local TCP port so that
   real gRPC clients (grpcurl, curl --http2-prior-knowledge, tonic) can
   be pointed at it for protocol conformance and connection-reuse
   testing.

   Usage: test_grpc_server [--port 19999] [--publish 1]

   With --publish 1 (default), a small canned SubscribeUpdate ping
   message is published to every open Subscribe stream a few times a
   second so streaming clients see traffic. */

#include "fd_grpc_server.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#if FD_HAS_HOSTED

#include <stdlib.h> /* aligned_alloc */

static ulong g_req_cnt   = 0UL;
static ulong g_close_cnt = 0UL;

static void
cb_request_msg( void *        ctx,
                ulong         conn_id,
                char const *  path,
                ulong         path_len,
                uchar const * msg,
                ulong         msg_sz ) {
  (void)ctx; (void)msg;
  g_req_cnt++;
  FD_LOG_NOTICE(( "request conn=%lu path=%.*s msg_sz=%lu", conn_id, (int)path_len, path, msg_sz ));
}

static void
cb_stream_close( void * ctx,
                 ulong  conn_id ) {
  (void)ctx;
  g_close_cnt++;
  FD_LOG_NOTICE(( "stream close conn=%lu", conn_id ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ushort port    = fd_env_strip_cmdline_ushort( &argc, &argv, "--port",    NULL, (ushort)19999 );
  int    publish = fd_env_strip_cmdline_int   ( &argc, &argv, "--publish", NULL, 1             );

  fd_grpc_server_params_t params = {
    .max_conn_cnt    = 8UL,
    .conn_rx_buf_sz  = 1UL<<16,
    .conn_tx_buf_sz  = 1UL<<17,
    .conn_out_buf_sz = 1UL<<17,
    .max_request_sz  = 1UL<<16,
    .stream_path     = "/geyser.Geyser/Subscribe",
    .version_path    = "/geyser.Geyser/GetVersion",
    .version_resp    = "{\"version\":\"0.0.0\",\"package\":\"test-grpc-server\"}",
  };

  fd_grpc_server_callbacks_t callbacks = {
    .request_msg  = cb_request_msg,
    .stream_close = cb_stream_close,
  };

  ulong  footprint = fd_grpc_server_footprint( params );
  void * mem       = aligned_alloc( fd_grpc_server_align(), footprint );
  FD_TEST( mem );

  fd_grpc_server_t * server = fd_grpc_server_join( fd_grpc_server_new( mem, params, &callbacks, NULL ) );
  FD_TEST( server );

  int fd = fd_grpc_server_listen( server, FD_IP4_ADDR( 127,0,0,1 ), port );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "listen failed (%i)", -fd ));
  FD_LOG_NOTICE(( "test grpc server listening at 127.0.0.1:%hu", port ));

  /* Canned SubscribeUpdate.ping (field 6, empty message): tag 0x32 len 0. */
  static uchar const ping_msg[] = { 0x32, 0x00 };

  long next_publish = fd_log_wallclock();
  for(;;) {
    int charge_busy = 0;
    fd_grpc_server_poll( server, &charge_busy );

    long now = fd_log_wallclock();
    if( publish && now>=next_publish ) {
      for( ulong i=0UL; i<params.max_conn_cnt; i++ ) {
        if( fd_grpc_server_has_stream( server, i ) ) {
          fd_grpc_server_publish( server, i, ping_msg, sizeof(ping_msg) );
        }
      }
      next_publish = now + (long)250e6; /* 250ms */
    }

    if( !charge_busy ) fd_log_sleep( (long)200e3 ); /* 200us */
  }

  /* unreachable */
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED" ));
  fd_halt();
  return 0;
}

#endif
