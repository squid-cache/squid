
/*
 * $Id: StoreIOBuffer.h,v 1.2 2003/01/23 00:37:14 robertc Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_STOREIORESULT_H
#define SQUID_STOREIORESULT_H

class StoreIOBuffer {
public:
    StoreIOBuffer():length(0), offset (0), data (NULL){flags.error = 0;}
    StoreIOBuffer(size_t aLength, off_t anOffset, char *someData) :
      length (aLength), offset (anOffset), data (someData)
      {
	flags.error = 0;
      }
    struct {
	int error:1;
    } flags;
    size_t length;
    off_t offset;
    char *data;
};

#endif /* SQUID_STOREIORESULT_H */
