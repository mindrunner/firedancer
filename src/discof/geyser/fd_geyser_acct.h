#ifndef HEADER_fd_src_discof_geyser_fd_geyser_acct_h
#define HEADER_fd_src_discof_geyser_fd_geyser_acct_h

/* fd_geyser_acct.h defines the wire format and producer helper for
   account-update fragments streamed from the execution tiles to the
   geyser tile over the *_geyser links.

   Each account update is a single fragment: a fixed fd_geyser_acct_hdr_t
   header immediately followed by up to (link_mtu - sizeof(hdr)) bytes of
   account data.  Account data larger than that is truncated and the
   TRUNCATED flag is set -- this mirrors the existing solcap account
   capture path, which likewise caps account data at a single 64 KiB
   fragment (SOLCAP_WRITE_ACCOUNT_DATA_MTU).  Streaming full data for
   oversized accounts via fragment reassembly is a later enhancement.

   The links are wired UNRELIABLE so a slow or dead geyser consumer can
   never backpressure the consensus-critical execution tiles. */

#include "../../disco/stem/fd_stem.h"
#include "../../disco/fd_disco_base.h"
#include "../../tango/fd_tango_base.h"

#define FD_GEYSER_ACCT_FLAG_HAS_SIG    (1U)
#define FD_GEYSER_ACCT_FLAG_TRUNCATED  (2U)

struct __attribute__((packed)) fd_geyser_acct_hdr {
  uchar pubkey[ 32 ];
  uchar owner[ 32 ];
  uchar txn_signature[ 64 ];
  ulong lamports;
  ulong slot;
  uint  executable;  /* 0 or 1 */
  uint  flags;       /* FD_GEYSER_ACCT_FLAG_* */
  /* inline account data follows: (frag_sz - sizeof(fd_geyser_acct_hdr_t)) bytes */
};

typedef struct fd_geyser_acct_hdr fd_geyser_acct_hdr_t;

/* fd_geyser_acct_publish stages and publishes one account-update
   fragment onto an execution tile's *_geyser out link.  *pchunk is
   advanced.  A no-op is NOT performed here for disabled links; callers
   must skip the call when the link is absent (out_idx==ULONG_MAX). */

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
  ulong cap        = mtu - hdr_sz;
  ulong inline_len = fd_ulong_min( data_len, cap );
  if( FD_UNLIKELY( !data ) ) inline_len = 0UL;

  uchar *                dst = fd_chunk_to_laddr( mem, *pchunk );
  fd_geyser_acct_hdr_t * h   = (fd_geyser_acct_hdr_t *)dst;
  fd_memcpy( h->pubkey, pubkey, 32UL );
  fd_memcpy( h->owner,  owner,  32UL );
  if( has_sig ) fd_memcpy( h->txn_signature, sig, 64UL );
  else          fd_memset( h->txn_signature, 0,   64UL );
  h->lamports   = lamports;
  h->slot       = slot;
  h->executable = (uint)( !!executable );
  h->flags      = (uint)( ( has_sig        ? FD_GEYSER_ACCT_FLAG_HAS_SIG   : 0U ) |
                          ( data_len>cap   ? FD_GEYSER_ACCT_FLAG_TRUNCATED : 0U ) );
  if( inline_len ) fd_memcpy( dst+hdr_sz, data, inline_len );

  ulong sz = hdr_sz + inline_len;
  fd_stem_publish( stem, out_idx, 0UL, *pchunk, sz, fd_frag_meta_ctl( 0UL, 1, 1, 0 ), 0UL, 0UL );
  *pchunk = fd_dcache_compact_next( *pchunk, sz, chunk0, wmark );
}

#endif /* HEADER_fd_src_discof_geyser_fd_geyser_acct_h */
