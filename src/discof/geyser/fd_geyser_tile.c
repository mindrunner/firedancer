/* fd_geyser_tile.c implements a Yellowstone-compatible Geyser gRPC
   server (https://github.com/rpcpool/yellowstone-grpc).  A stock
   Yellowstone client can open the bidirectional `geyser.Geyser/Subscribe`
   stream and receive protobuf SubscribeUpdate messages.

   Phase 1 (this file) sources slot updates from the replay tile's
   replay_out link and serves SubscribeUpdateSlot at processed /
   confirmed / finalized commitment.  Account, transaction and block
   streaming land in later phases.

   The HTTP/2 + gRPC framing is handled by fd_grpc_server (the
   server-side counterpart to fd_grpc_client), which is driven from
   before_credit just like the rpc/gui tiles drive fd_http_server. */

#define _GNU_SOURCE /* SOCK_CLOEXEC, SOCK_NONBLOCK, MSG_NOSIGNAL */

#include "../replay/fd_replay_tile.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../waltz/grpc/fd_grpc_server.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <sys/socket.h>

#include "generated/fd_geyser_tile_seccomp.h"

#define IN_KIND_REPLAY (0)

#define GEYSER_MAX_IN_LINKS (8UL)
#define GEYSER_FILTER_KEY_MAX (32UL)
#define GEYSER_ENC_BUF_SZ (512UL)

/* Yellowstone SlotStatus enum values. */
#define GEYSER_SLOT_PROCESSED (0)
#define GEYSER_SLOT_CONFIRMED (1)
#define GEYSER_SLOT_FINALIZED (2)

/* Per-subscriber (per gRPC connection) state. */

struct geyser_sub {
  int   wants_slots;
  uint  commitment;
  char  filter_key[ GEYSER_FILTER_KEY_MAX ];
  ulong filter_key_len;
};

typedef struct geyser_sub geyser_sub_t;

struct fd_geyser_tile {
  fd_grpc_server_t * server;
  geyser_sub_t *     subs;        /* [max_conn_cnt] */
  ulong              max_conn_cnt;

  fd_keyswitch_t * keyswitch;

  long next_poll_deadline;

  uint   listen_addr;
  ushort listen_port;

  int    in_kind[ GEYSER_MAX_IN_LINKS ];
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ GEYSER_MAX_IN_LINKS ];

  uchar enc_buf[ GEYSER_ENC_BUF_SZ ];
};

typedef struct fd_geyser_tile fd_geyser_tile_t;

/* Server sizing derived from tile config. -----------------------------*/

static fd_grpc_server_params_t
derive_server_params( fd_topo_tile_t const * tile ) {
  ulong max_conn = fd_ulong_max( 1UL, tile->geyser.max_connections );
  /* send_buffer_size_mb is the total outbound budget, shared evenly
     across connections (each connection gets its own ring so a slow
     consumer is isolated and can be evicted without affecting others). */
  ulong total_out = tile->geyser.send_buffer_size_mb*(1UL<<20UL);
  if( !total_out ) total_out = 64UL*(1UL<<20UL);
  ulong per_conn_out = fd_ulong_max( 1UL<<16UL, total_out/max_conn );
  return (fd_grpc_server_params_t){
    .max_conn_cnt    = max_conn,
    .conn_rx_buf_sz  = 1UL<<16UL, /* 64 KiB */
    .conn_tx_buf_sz  = 1UL<<18UL, /* 256 KiB */
    .conn_out_buf_sz = per_conn_out,
    .max_request_sz  = 1UL<<16UL, /* 64 KiB */
  };
}

/* Minimal Protobuf scanning for SubscribeRequest. ---------------------*/

static ulong
geyser_pb_read_varint( uchar const * p,
                       ulong         sz,
                       ulong *       pos,
                       ulong *       out ) {
  ulong i = *pos;
  ulong val = 0UL;
  int   shift = 0;
  while( i<sz && shift<64 ) {
    uchar b = p[ i++ ];
    val |= (ulong)( b & 0x7FU ) << shift;
    if( !( b & 0x80U ) ) { *pos = i; *out = val; return 1UL; }
    shift += 7;
  }
  return 0UL; /* truncated */
}

/* Skip a field given its wire type.  Returns 1 on success. */
static ulong
geyser_pb_skip( uchar const * p,
                ulong         sz,
                ulong *       pos,
                uint          wire_type ) {
  ulong tmp;
  switch( wire_type ) {
    case 0: return geyser_pb_read_varint( p, sz, pos, &tmp );
    case 1: if( *pos+8UL>sz ) return 0; *pos += 8UL; return 1;
    case 5: if( *pos+4UL>sz ) return 0; *pos += 4UL; return 1;
    case 2: {
      if( !geyser_pb_read_varint( p, sz, pos, &tmp ) ) return 0;
      if( *pos+tmp>sz ) return 0;
      *pos += tmp;
      return 1;
    }
    default: return 0;
  }
}

/* Parse the key (field 1, string) out of a slots map entry submessage. */
static void
geyser_parse_slots_entry( uchar const *  entry,
                          ulong          entry_sz,
                          geyser_sub_t * sub ) {
  ulong pos = 0UL;
  while( pos<entry_sz ) {
    ulong tag;
    if( !geyser_pb_read_varint( entry, entry_sz, &pos, &tag ) ) return;
    uint field = (uint)( tag>>3 );
    uint wt    = (uint)( tag & 7U );
    if( field==1U && wt==2U ) {
      ulong len;
      if( !geyser_pb_read_varint( entry, entry_sz, &pos, &len ) ) return;
      if( pos+len>entry_sz ) return;
      ulong cpy = fd_ulong_min( len, GEYSER_FILTER_KEY_MAX-1UL );
      fd_memcpy( sub->filter_key, entry+pos, cpy );
      sub->filter_key_len = cpy;
      return;
    } else {
      if( !geyser_pb_skip( entry, entry_sz, &pos, wt ) ) return;
    }
  }
}

/* Parse a SubscribeRequest.  Phase 1 extracts: whether a `slots` filter
   (field 2) is present, its first map key, and the requested commitment
   (field 6). */
static void
geyser_parse_subscribe_request( uchar const *  msg,
                                ulong          msg_sz,
                                geyser_sub_t * sub ) {
  ulong pos = 0UL;
  while( pos<msg_sz ) {
    ulong tag;
    if( !geyser_pb_read_varint( msg, msg_sz, &pos, &tag ) ) return;
    uint field = (uint)( tag>>3 );
    uint wt    = (uint)( tag & 7U );

    if( field==2U && wt==2U ) {              /* slots map entry */
      ulong len;
      if( !geyser_pb_read_varint( msg, msg_sz, &pos, &len ) ) return;
      if( pos+len>msg_sz ) return;
      sub->wants_slots = 1;
      if( !sub->filter_key_len ) geyser_parse_slots_entry( msg+pos, len, sub );
      pos += len;
    } else if( field==6U && wt==0U ) {       /* commitment */
      ulong c;
      if( !geyser_pb_read_varint( msg, msg_sz, &pos, &c ) ) return;
      sub->commitment = (uint)c;
    } else {
      if( !geyser_pb_skip( msg, msg_sz, &pos, wt ) ) return;
    }
  }
}

/* Encode a SubscribeUpdate carrying a SubscribeUpdateSlot. */
static ulong
geyser_encode_slot_update( uchar *       out,
                           ulong         out_sz,
                           ulong         slot,
                           ulong         parent,
                           int           has_parent,
                           int           status,
                           char const *  filter_key,
                           ulong         filter_key_len ) {
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, out, out_sz );

  /* SubscribeUpdate.filters = 1 (repeated string) */
  if( filter_key_len ) fd_pb_push_string( enc, 1U, filter_key, filter_key_len );

  /* SubscribeUpdate.slot = 3 (SubscribeUpdateSlot) */
  fd_pb_submsg_open( enc, 3U );
    fd_pb_push_uint64( enc, 1U, slot );             /* slot   */
    if( has_parent ) fd_pb_push_uint64( enc, 2U, parent ); /* parent */
    fd_pb_push_int32 ( enc, 3U, status );           /* status */
  fd_pb_submsg_close( enc );

  return fd_pb_encoder_out_sz( enc );
}

static void
geyser_publish_slot( fd_geyser_tile_t * ctx,
                     ulong              slot,
                     ulong              parent,
                     int                has_parent,
                     int                status ) {
  for( ulong conn_id=0UL; conn_id<ctx->max_conn_cnt; conn_id++ ) {
    geyser_sub_t * sub = &ctx->subs[ conn_id ];
    if( !sub->wants_slots ) continue;
    if( !fd_grpc_server_has_stream( ctx->server, conn_id ) ) continue;

    ulong sz = geyser_encode_slot_update( ctx->enc_buf, sizeof(ctx->enc_buf),
                                          slot, parent, has_parent, status,
                                          sub->filter_key, sub->filter_key_len );
    if( FD_UNLIKELY( !fd_grpc_server_publish( ctx->server, conn_id, ctx->enc_buf, sz ) ) ) {
      /* Slow consumer: evict rather than stall the validator. */
      fd_grpc_server_close( ctx->server, conn_id );
    }
  }
}

/* fd_grpc_server upcalls. ---------------------------------------------*/

static void
geyser_cb_request_msg( void *        _ctx,
                       ulong         conn_id,
                       char const *  path,
                       ulong         path_len,
                       uchar const * msg,
                       ulong         msg_sz ) {
  (void)path; (void)path_len;
  fd_geyser_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( conn_id>=ctx->max_conn_cnt ) ) return;
  geyser_sub_t * sub = &ctx->subs[ conn_id ];
  geyser_parse_subscribe_request( msg, msg_sz, sub );
}

static void
geyser_cb_stream_close( void * _ctx,
                        ulong  conn_id ) {
  fd_geyser_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( conn_id>=ctx->max_conn_cnt ) ) return;
  fd_memset( &ctx->subs[ conn_id ], 0, sizeof(geyser_sub_t) );
}

static fd_grpc_server_callbacks_t const geyser_grpc_callbacks = {
  .request_msg  = geyser_cb_request_msg,
  .stream_close = geyser_cb_stream_close,
};

/* Tile callbacks. -----------------------------------------------------*/

static void
during_housekeeping( fd_geyser_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->keyswitch && fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
before_credit( fd_geyser_tile_t *  ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  long now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->next_poll_deadline ) ) {
    fd_grpc_server_poll( ctx->server, charge_busy );
    ctx->next_poll_deadline = fd_tickcount() + (long)( fd_tempo_tick_per_ns( NULL )*128L*1000L );
  }
}

static inline int
returnable_frag( fd_geyser_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz     FD_PARAM_UNUSED,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  (void)stem;
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]!=IN_KIND_REPLAY ) ) return 0;

  switch( sig ) {
    case REPLAY_SIG_SLOT_COMPLETED: {
      fd_replay_slot_completed_t const * m = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      geyser_publish_slot( ctx, m->slot, m->parent_slot, 1, GEYSER_SLOT_PROCESSED );
      break;
    }
    case REPLAY_SIG_OC_ADVANCED: {
      fd_replay_oc_advanced_t const * m = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      geyser_publish_slot( ctx, m->slot, 0UL, 0, GEYSER_SLOT_CONFIRMED );
      break;
    }
    case REPLAY_SIG_ROOT_ADVANCED: {
      fd_replay_root_advanced_t const * m = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      geyser_publish_slot( ctx, m->slot, 0UL, 0, GEYSER_SLOT_FINALIZED );
      break;
    }
    default:
      break;
  }
  return 0;
}

/* Init. ---------------------------------------------------------------*/

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_geyser_tile_t), fd_grpc_server_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_grpc_server_params_t params = derive_server_params( tile );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_geyser_tile_t), sizeof(fd_geyser_tile_t)                       );
  l = FD_LAYOUT_APPEND( l, fd_grpc_server_align(),    fd_grpc_server_footprint( params )             );
  l = FD_LAYOUT_APPEND( l, alignof(geyser_sub_t),     tile->geyser.max_connections*sizeof(geyser_sub_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_grpc_server_params_t params = derive_server_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_geyser_tile_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_tile_t), sizeof(fd_geyser_tile_t)            );
  void *             _server = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_server_align(),    fd_grpc_server_footprint( params )  );
  void *             _subs   = FD_SCRATCH_ALLOC_APPEND( l, alignof(geyser_sub_t),     tile->geyser.max_connections*sizeof(geyser_sub_t) );

  fd_memset( ctx,   0, sizeof(fd_geyser_tile_t) );
  fd_memset( _subs, 0, tile->geyser.max_connections*sizeof(geyser_sub_t) );

  ctx->subs         = _subs;
  ctx->max_conn_cnt = tile->geyser.max_connections;
  ctx->listen_addr  = tile->geyser.listen_addr;
  ctx->listen_port  = tile->geyser.listen_port;

  ctx->server = fd_grpc_server_join( fd_grpc_server_new( _server, params, &geyser_grpc_callbacks, ctx ) );
  FD_TEST( ctx->server );

  int fd = fd_grpc_server_listen( ctx->server, tile->geyser.listen_addr, tile->geyser.listen_port );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "fd_grpc_server_listen failed (%i-%s)", -fd, fd_io_strerror( -fd ) ));
  FD_LOG_NOTICE(( "geyser gRPC server listening at " FD_IP4_ADDR_FMT ":%u",
                  FD_IP4_ADDR_FMT_ARGS( tile->geyser.listen_addr ), tile->geyser.listen_port ));
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_geyser_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_tile_t), sizeof(fd_geyser_tile_t) );

  if( FD_LIKELY( tile->id_keyswitch_obj_id!=ULONG_MAX ) ) {
    ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  }

  ctx->next_poll_deadline = fd_tickcount();

  FD_TEST( tile->in_cnt<=GEYSER_MAX_IN_LINKS );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link      = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "geyser: unexpected in-link %s", link->name ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow" ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_geyser_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_tile_t), sizeof(fd_geyser_tile_t) );

  populate_sock_filter_policy_fd_geyser_tile( out_cnt, out,
                                              (uint)fd_log_private_logfile_fd(),
                                              (uint)fd_grpc_server_listen_fd( ctx->server ) );
  return sock_filter_policy_fd_geyser_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_geyser_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_tile_t), sizeof(fd_geyser_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = fd_grpc_server_listen_fd( ctx->server );
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, listen socket, stderr, logfile, plus one spare for accept(). */
  ulong base = 5UL;
  return base + tile->geyser.max_connections;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_geyser_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_geyser_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_geyser = {
  .name                     = "geyser",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
