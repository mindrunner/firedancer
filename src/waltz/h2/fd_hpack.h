#ifndef HEADER_fd_src_waltz_h2_fd_hpack_h
#define HEADER_fd_src_waltz_h2_fd_hpack_h

/* fd_hpack.h provides APIs for HPACK compression and decompression.

   Supports the static table and Huffman string coding.  Does not use
   the dynamic table while encoding.

   Decoding supports an optional dynamic table (fd_hpack_rd_init_dt).
   This is required on the server side: even though fd_h2 advertises
   SETTINGS_HEADER_TABLE_SIZE=0, RFC 7541 sets the initial dynamic table
   size to 4096, so a peer may legally emit dynamic table insertions and
   references for anything it sends before it has processed our
   SETTINGS (e.g. a burst of pipelined requests on a fresh connection).
   Decoders without a dynamic table (fd_hpack_rd_init) reject such
   header blocks with a COMPRESSION error, which tears down the whole
   connection. */

#include "fd_h2_base.h"

/* fd_h2_hdr_t points to an HTTP/2 header name:value pair.

   {name,value} point to decoded header values stored either in the
   hardcoded HPACK static table, the binary frame, or a scratch buffer.
   It is not guaranteed that these are valid ASCII.  These are NOT
   null-terminated.

   (hint&FD_H2_HDR_HINT_INDEXED) indicates that the HPACK coding of the
   header referenced a static table entry.  The index of the entry is
   in the low 6 bits.

   (hint&FD_H2_HDR_HINT_HUFFMAN) is internal and can be safely ignored,
   as fd_hpack_rd_next takes care of Huffman coding. */

struct fd_h2_hdr {
  char const * name;
  char const * value;
  ushort       name_len;
  ushort       hint;
  uint         value_len;
};

typedef struct fd_h2_hdr fd_h2_hdr_t;

#define FD_H2_HDR_HINT_NAME_HUFFMAN  ((ushort)0x8000) /* name is huffman coded */
#define FD_H2_HDR_HINT_VALUE_HUFFMAN ((ushort)0x4000) /* value is huffman coded */
#define FD_H2_HDR_HINT_HUFFMAN ((ushort)(FD_H2_HDR_HINT_NAME_HUFFMAN|FD_H2_HDR_HINT_VALUE_HUFFMAN))
#define FD_H2_HDR_HINT_NAME_INDEXED  ((ushort)0x2000) /* name was indexed from table */
#define FD_H2_HDR_HINT_VALUE_INDEXED ((ushort)0x1000) /* value was indexed from table */
#define FD_H2_HDR_HINT_INDEXED ((ushort)(FD_H2_HDR_HINT_NAME_INDEXED|FD_H2_HDR_HINT_VALUE_INDEXED))
#define FD_H2_HDR_HINT_INSERT        ((ushort)0x0800) /* internal: add entry to dynamic table */
#define FD_H2_HDR_HINT_GET_INDEX(hint) ((uchar)((hint)&0xFF))

/* fd_hpack_dt_t is an HPACK decoder-side dynamic table (RFC 7541 §2.3.2
   and §4).  Sized for the protocol-initial SETTINGS_HEADER_TABLE_SIZE
   of 4096 bytes (each entry has 32 bytes of nominal overhead, bounding
   the entry count at 128).  Zero/init to reset (e.g. per connection). */

#define FD_HPACK_DT_MAX       (4096UL)
#define FD_HPACK_DT_ENTRY_MAX ( 128UL)

struct fd_hpack_dt_entry {
  ushort off;       /* offset of name bytes in arena */
  ushort name_len;
  ushort value_len; /* value bytes immediately follow name bytes */
};

typedef struct fd_hpack_dt_entry fd_hpack_dt_entry_t;

struct fd_hpack_dt {
  ulong max_sz;    /* current max table size (RFC size incl 32 B/entry) */
  ulong used_sz;   /* current table size (RFC size incl 32 B/entry) */
  ulong entry_cnt;
  fd_hpack_dt_entry_t entry[ FD_HPACK_DT_ENTRY_MAX ]; /* [0]=oldest */
  uchar arena[ FD_HPACK_DT_MAX ]; /* entry bytes, packed oldest first */
};

typedef struct fd_hpack_dt fd_hpack_dt_t;

/* An fd_hpack_rd_t object reads a block of HPACK-encoded HTTP/2
   headers.  For example usage, see test_hpack. */

struct fd_hpack_rd {
  uchar const *   src;
  uchar const *   src_end;
  fd_hpack_dt_t * dt;  /* optional dynamic table, may be NULL */
  uint            err; /* sticky decode error (set by init_dt) */
};

typedef struct fd_hpack_rd fd_hpack_rd_t;

FD_PROTOTYPES_BEGIN

/* fd_hpack_dt_init resets a dynamic table to empty with the RFC 7541
   initial max size (4096). */

fd_hpack_dt_t *
fd_hpack_dt_init( fd_hpack_dt_t * dt );

/* fd_hpack_rd_init initializes a hpack_rd for reading of the header
   block in src.  hpack_rd has a read interest in src for its entire
   lifetime.  Dynamic table references in the block fail with
   FD_H2_ERR_COMPRESSION (equivalent to an empty, zero-size table). */

fd_hpack_rd_t *
fd_hpack_rd_init( fd_hpack_rd_t * rd,
                  uchar const *   src,
                  ulong           srcsz );

/* fd_hpack_rd_init_dt is fd_hpack_rd_init with a dynamic table.  dt
   persists across header blocks of a connection; the caller resets it
   with fd_hpack_dt_init when the connection is (re)established.
   Leading dynamic table size updates in the block are applied to dt.
   Pointers returned by fd_hpack_rd_next may reference dt's storage and
   are invalidated by the next fd_hpack_rd_next call on any reader
   using this dt. */

fd_hpack_rd_t *
fd_hpack_rd_init_dt( fd_hpack_rd_t * rd,
                     uchar const *   src,
                     ulong           srcsz,
                     fd_hpack_dt_t * dt );

/* fd_hpack_rd_done returns 1 if all header entries were read from
   hpack_rd.  Returns 0 if fd_hpack_rd_next should be called again. */

static inline int
fd_hpack_rd_done( fd_hpack_rd_t const * rd ) {
  return !rd->err && rd->src >= rd->src_end;
}

/* fd_hpack_rd_next reads the next header from hpack_rd.  hdr is
   populated with pointers to the decoded data.  These pointers either
   point into hpack_rd->src or *scratch.

   *scratch is assumed to point to the next free byte in a scratch
   buffer.  scratch_end points one past the last byte of the scratch
   buffer.

   Returns FD_H2_SUCCESS, populates header, and updates *scratch on
   success.  On failure, returns FD_H2_ERR_COMPRESSION and leaves
   *scratch intact.  Reasons for failure include HPACK parse error,
   out-of-bounds table index, use of the dynamic table, Huffman coding
   error, or out of scratch space.  The caller should assume that *hdr
   and **scratch (the free bytes in the scratch buffer, not the pointer
   itself) are invalidated/filled with garbage on failure. */

uint
fd_hpack_rd_next( fd_hpack_rd_t * hpack_rd,
                  fd_h2_hdr_t *   hdr,
                  uchar **        scratch,
                  uchar *         scratch_end );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_h */
