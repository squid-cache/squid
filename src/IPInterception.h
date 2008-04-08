/*
 * $Id: IPInterception.h,v 1.7 2007/12/14 23:11:45 amosjeffries Exp $
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
#ifndef SQUID_IPINTERCEPTION_H
#define SQUID_IPINTERCEPTION_H

class IPAddress;

/**
 \defgroup IPInterceptAPI IP Interception and Transparent Proxy API
 \ingroup SquidComponent
 \par
 * There is no formal state-machine for transparency and interception
 * instead there is this neutral API which other connection state machines
 * and the comm layer use to co-ordinate their own state for transparency.
 */
class IPIntercept
{
public:
    int NatLookup(int fd, const IPAddress &me, const IPAddress &peer, IPAddress &dst);
}

#if !defined(IP_TRANSPARENT)
/// \ingroup IPInterceptAPI
#define IP_TRANSPARENT 19
#endif

/**
 \ingroup IPInterceptAPI
 * Globally available instance of the IP Interception manager.
 */
extern IPIntercept IPInterceptor;

#endif /* SQUID_IPINTERCEPTION_H */
