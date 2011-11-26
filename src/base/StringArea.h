/*
 * StringArea.h
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
 */

#ifndef SQUID_STRINGAREA_H
#define SQUID_STRINGAREA_H

#if HAVE_CSTRING
#include <cstring>
#endif

/** A char* plus length combination. Useful for temporary storing
 * and quickly looking up strings.
 *
 * The pointed-to string may not be null-terminated.
 * The pointed-to string is not copied.
 *
 * Not meant for stand-alone storage. Validity of the
 * pointed-to string is responsibility of the caller.
 */
class StringArea
{
public:
    /// build a StringArea by explicitly assigning pointed-to area and and length
    StringArea(const char * ptr, size_t len): theStart(ptr), theLen(len) {}
    bool operator==(const StringArea &s) const { return theLen==s.theLen && memcmp(theStart,s.theStart,theLen)==0; }
    bool operator!=(const StringArea &s) const { return !operator==(s); }
    bool operator< ( const StringArea &s) const {
        return (theLen < s.theLen || (theLen == s.theLen && memcmp(theStart,s.theStart,theLen) < 0)) ;
    }

private:
    /// pointed to the externally-managed memory area
    const char *theStart;
    /// length of the string
    size_t theLen;
};

#endif /* SQUID_STRINGAREA_H */
