/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    conffile.hh
//          Fri Sep 15 2000
//
// (c) 2000 Lehrgebiet Rechnernetze und Verteilte Systeme
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
// Revision 1.2  2000/09/21 10:17:17  cached
// namespace std:: needed for Sun WS compiler.
//
// Revision 1.1  2000/09/21 09:45:14  voeckler
// Initial revision
//
//
#ifndef _CONFFILE_HH
#define _CONFFILE_HH

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */


#if !defined(DEFAULT_SQUID_CONF)
#define DEFAULT_SQUID_CONF "/usr/local/squid/etc/squid.conf"
#endif

#include <vector>

struct CacheDir {
  enum CacheDirType { CDT_NONE, CDT_UFS, CDT_AUFS, CDT_DISKD, CDT_OTHER };

  const char*  base;
  CacheDirType type;
  size_t       size;
  unsigned     level[2];
};

typedef std::vector<CacheDir> CacheDirVector;

int
readConfigFile( CacheDirVector& cachedir, 
		const char* fn = DEFAULT_SQUID_CONF, 
		FILE* debug = 0 );
  // purpose: read squid.conf file and extract cache_dir entries
  // paramtr: cachedir (OUT): vector with an entry for each cache_dir found
  //          fn (IN): file name of squid.conf to use
  //          debug (IO): if not null, place debug information there
  // returns: number of entries, or negative to warn of errors

#endif // _CONFFILE_HH
