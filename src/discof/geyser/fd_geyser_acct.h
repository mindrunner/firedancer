#ifndef HEADER_fd_src_discof_geyser_fd_geyser_acct_h
#define HEADER_fd_src_discof_geyser_fd_geyser_acct_h

/* fd_geyser_acct.h defines the wire format and producer helper for
   account-update fragments streamed from the execution tiles to the
   geyser tile over the *_geyser links.

   An account update is a logical message [ fd_geyser_acct_hdr_t | data ]
   split across one or more link fragments using the SOM/EOM control
   bits: the first fragment carries the header plus the first chunk of
   data and the SOM bit; subsequent fragments carry data only; the final
   fragment carries the EOM bit.  A small account fits in a single
   fragment with both SOM and EOM set.  The geyser tile reassembles per
   in-link.

   Account data is capped at FD_GEYSER_ACCT_DATA_MAX; data beyond that is
   truncated and the TRUNCATED flag is set (rare -- only the largest
   program/PDA accounts exceed it, and they seldom change).  The cap
   bounds the geyser tile's per-link reassembly buffers and per-conn
   outbound rings.

   The links are wired UNRELIABLE so a slow or dead geyser consumer can
   never backpressure the consensus-critical execution tiles. */

#include "../../disco/stem/fd_stem.h"
#include "../../disco/fd_disco_base.h"
#include "../../tango/fd_tango_base.h"

#define FD_GEYSER_ACCT_FLAG_HAS_SIG    (1U)
#define FD_GEYSER_ACCT_FLAG_TRUNCATED  (2U)

/* Max account data streamed in full (fragments reassembled).  1 MiB
   covers essentially all accounts that change in a transaction; larger
   accounts are truncated.  Bump (with the matching memory cost in the
   geyser tile) to raise the ceiling toward FD_RUNTIME_ACC_SZ_MAX. */
#define FD_GEYSER_ACCT_DATA_MAX (1UL<<20)

struct __attribute__((packed)) fd_geyser_acct_hdr {
  uchar pubkey[ 32 ];
  uchar owner[ 32 ];
  uchar txn_signature[ 64 ];
  ulong lamports;
  ulong slot;
  ulong data_len;    /* total streamed data length (sum of all fragments'
                        data); lets the reassembler discard an account
                        left incomplete by an unreliable-link overrun */
  uint  executable;  /* 0 or 1 */
  uint  flags;       /* FD_GEYSER_ACCT_FLAG_* */
  /* the first fragment's header is followed by the first data chunk */
};

typedef struct fd_geyser_acct_hdr fd_geyser_acct_hdr_t;

/* fd_geyser_acct_publish stages and publishes one account-update logical
   message (one or more fragments) onto an execution tile's *_geyser out
   link.  *pchunk is advanced.  Callers must skip the call when the link
   is absent (out_idx==ULONG_MAX). */

static inline void
fd_geyser_acct_publish( fd_stem_context_t * stem,
                        ulong               out_idx,
                        fd_wksp_t *         mem,
                        ulong *             pchunk,
                        ulong               chunk0,
                        ulong               wmark,
                        ulong               mtu,
                        uchar const         pubkey[ 32 ],
                        uchar const         owner[ 32 ],
                        ulong               lamports,
                        int                 executable,
                        uchar const *       data,
                        ulong               data_len,
                        ulong               slot,
                        uchar const         sig[ 64 ],
                        int                 has_sig ) {
  ulong hdr_sz = sizeof(fd_geyser_acct_hdr_t);
  if( FD_UNLIKELY( mtu<=hdr_sz ) ) return;
  if( FD_UNLIKELY( !data ) ) data_len = 0UL;

  ulong stream_len = fd_ulong_min( data_len, FD_GEYSER_ACCT_DATA_MAX );

  /* First fragment: header + first data chunk, SOM set. */
  ulong first_data = fd_ulong_min( stream_len, mtu - hdr_sz );

  uchar *                dst = fd_chunk_to_laddr( mem, *pchunk );
  fd_geyser_acct_hdr_t * h   = (fd_geyser_acct_hdr_t *)dst;
  fd_memcpy( h->pubkey, pubkey, 32UL );
  fd_memcpy( h->owner,  owner,  32UL );
  if( has_sig ) fd_memcpy( h->txn_signature, sig, 64UL );
  else          fd_memset( h->txn_signature, 0,   64UL );
  h->lamports   = lamports;
  h->slot       = slot;
  h->data_len   = stream_len;
  h->executable = (uint)( !!executable );
  h->flags      = (uint)( ( has_sig                          ? FD_GEYSER_ACCT_FLAG_HAS_SIG   : 0U ) |
                          ( data_len>FD_GEYSER_ACCT_DATA_MAX  ? FD_GEYSER_ACCT_FLAG_TRUNCATED : 0U ) );
  if( first_data ) fd_memcpy( dst+hdr_sz, data, first_data );

  ulong sz0  = hdr_sz + first_data;
  int   eom0 = ( first_data==stream_len );
  fd_stem_publish( stem, out_idx, 0UL, *pchunk, sz0, fd_frag_meta_ctl( 0UL, 1, eom0, 0 ), 0UL, 0UL );
  *pchunk = fd_dcache_compact_next( *pchunk, sz0, chunk0, wmark );

  /* Remaining data fragments. */
  ulong off = first_data;
  while( off<stream_len ) {
    ulong chunk_sz = fd_ulong_min( stream_len-off, mtu );
    uchar * d = fd_chunk_to_laddr( mem, *pchunk );
    fd_memcpy( d, data+off, chunk_sz );
    off += chunk_sz;
    int eom = ( off==stream_len );
    fd_stem_publish( stem, out_idx, 0UL, *pchunk, chunk_sz, fd_frag_meta_ctl( 0UL, 0, eom, 0 ), 0UL, 0UL );
    *pchunk = fd_dcache_compact_next( *pchunk, chunk_sz, chunk0, wmark );
  }
}

#endif /* HEADER_fd_src_discof_geyser_fd_geyser_acct_h */
