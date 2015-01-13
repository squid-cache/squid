/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    squid-tlv.hh
//          Tue Jun 15 1999
//
// (c) 1999 Lehrgebiet Rechnernetze und Verteilte Systeme
//          Universit?t Hannover, Germany
//
// Permission to use, copy, modify, distribute, and sell this software
// and its documentation for any purpose is hereby granted without fee,
// provided that (i) the above copyright notices and this permission
// notice appear in all copies of the software and related documentation,
// and (ii) the names of the Lehrgebiet Rechnernetze und Verteilte
// Systeme and the University of Hannover may not be used in any
// advertising or publicity relating to the software without the
// specific, prior written permission of Lehrgebiet Rechnernetze und
// Verteilte Systeme and the University of Hannover.
//
// THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
// EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
//
// IN NO EVENT SHALL THE LEHRGEBIET RECHNERNETZE UND VERTEILTE SYSTEME OR
// THE UNIVERSITY OF HANNOVER BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
// INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT
// ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY,
// ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
// SOFTWARE.
//
// Revision 1.1  1999/06/15 21:10:16  voeckler
// Initial revision
//
#ifndef SQUID_TLV_HH
#define SQUID_TLV_HH

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// taken from Squid-2.x
// NOTE!  We must preserve the order of this list!
enum SquidMetaType {
  STORE_META_VOID,		// should not come up 
  STORE_META_KEY_URL,		// key w/ keytype 
  STORE_META_KEY_SHA,
  STORE_META_KEY_MD5,
  STORE_META_URL,		// the url , if not in the header
  STORE_META_STD,		// standard metadata
  STORE_META_HITMETERING,	// reserved for hit metering
  STORE_META_VALID,
  STORE_META_VARY_HEADERS,	// Stores Vary request headers
  STORE_META_STD_LFS,		// standard metadata in lfs format
  STORE_META_OBJSIZE		// object size, if its known
};

// taken from Squid-2.x
struct StoreMetaStd {
  time_t  timestamp;
  time_t  lastref;
  time_t  expires;
  time_t  lastmod;
  size_t  swap_file_sz;
  uint16_t refcount;
  uint16_t flags;
};

struct StoreMetaStdLFS {
  time_t  timestamp;
  time_t  lastref;
  time_t  expires;
  time_t  lastmod;
  uint64_t swap_file_sz;
  uint16_t refcount;
  uint16_t flags;
};

struct SquidTLV {
  // create a shallow reference pointing into the "buffer" variable
  // do not copy --> saves times, saves memory.
  SquidTLV( SquidMetaType _type, size_t _size = 0, void* _data = 0 );
  ~SquidTLV() {}

  SquidTLV*      next;
  size_t	 size;
  SquidMetaType  type;
  char*          data;
};

class SquidMetaList {
public:
  SquidMetaList();
  ~SquidMetaList();

  void append( SquidMetaType type, size_t size, void* data );
  const SquidTLV* search( SquidMetaType type ) const;

private:
  SquidTLV* head;
  SquidTLV* tail;
};

#endif // SQUID_TLV_HH
