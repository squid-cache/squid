
/*
 * $Id: Range.h,v 1.2 2003/01/23 00:36:47 robertc Exp $
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

#ifndef SQUID_RANGE_H
#define SQUID_RANGE_H

/* represents [start, end) */

template <class C>

class Range
{

public:
    Range (C start_, C end_);
    C start;
    C end;
    Range intersection (Range const &);
    size_t size() const;
};

template<class C>
Range<C>::Range (C start_, C end_) : start(start_), end(end_){}

template<class C>

class Range<C>
            Range<C>::intersection (Range const &rhs)
{
    Range<C> result (XMAX(start, rhs.start), XMIN(end, rhs.end));
    return result;
}

template<class C>
size_t
Range<C>::size() const
{
    return end > start ? end - start : 0;
}

#endif /* SQUID_RANGE_H */
