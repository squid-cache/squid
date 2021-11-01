/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    copyout.hh
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
// Revision 1.1  1999/06/15 21:10:47  voeckler
// Initial revision
//
#ifndef _COPYOUT_HH
#define _COPYOUT_HH

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */

int
assert_copydir( const char* copydir );
  // purpose: check, if copydir is a directory and that we can write into it.
  // paramtr: copydir (IN): name of directory for copying bodies.
  // returns: 0 if ok, -1 otherwise.
  // further: errors are handled within. If the directory does not exist,
  //          the assertion function will try to create it.

bool
copy_out( size_t filesize, size_t metasize, unsigned debug,
	  const char* fn, const char* url, const char* copydir,
	  bool copyHdr = true );
  // purpose: copy content from squid disk file into separate file
  // paramtr: filesize (IN): complete size of input file
  //          metasize (IN): size of metadata to skip
  //          fn (IN): current filename of squid disk file
  //          url (IN): currently looked at URL to generate separate file
  //          copydir (IN): base directory where to generate the file
  //          copyHdr (IN): copy HTTP header, too, if set to true.
  // returns: true, if successful, false otherwise.

#endif // _COPYOUT_HH
