
/*
 * $Id: ICAPClient.h,v 1.3 2005/12/22 22:26:31 wessels Exp $
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

#ifndef SQUID_ICAPCLIENT_H
#define SQUID_ICAPCLIENT_H

#include "MsgPipe.h"        // TODO: move; needed for ICAPInitXaction()
#include "ICAPServiceRep.h" // TODO: move; needed for ICAPInitXaction()

// ICAP-related things needed by code unaware of ICAP internals.

extern void ICAPInitModule();
extern void ICAPCleanModule();

// let ICAP initialize ICAP-specific ends of message pipes

class MsgPipe;
extern void ICAPInitXaction(ICAPServiceRep::Pointer, MsgPipe::Pointer virgin, MsgPipe::Pointer adapted);

#endif /* SQUID_ICAPCLIENT_H */
