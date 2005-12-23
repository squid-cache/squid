
/*
 * $Id: ICAPElements.h,v 1.3 2005/12/22 22:26:31 wessels Exp $
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

#ifndef SQUID_ICAPELEMENTS_H
#define SQUID_ICAPELEMENTS_H

// ICAP-related things shared by many ICAP classes

// A "fake" class to encapsulate ICAP-related declarations without
// adding namespaces to Squid. Eventually, namespaces should be added.

struct ICAP
{
    typedef enum { methodNone, methodReqmod, methodRespmod, methodOptions } Method;
    typedef enum { pointNone, pointPreCache, pointPostCache } VectPoint;

    // recommended initial size and max capacity for MsgPipe buffer
    enum { MsgPipeBufSizeMin = (4*1024), MsgPipeBufSizeMax = SQUID_TCP_SO_RCVBUF };

    static const char *crlf;
    static const char *methodStr(ICAP::Method);
    static const char *vectPointStr(ICAP::VectPoint);
};

#endif /* SQUID_ICAPCLIENT_H */
