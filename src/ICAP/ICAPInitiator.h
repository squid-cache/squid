
/*
 * $Id: ICAPInitiator.h,v 1.1 2007/04/06 04:50:07 rousskov Exp $
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

#ifndef SQUID_ICAPINITIATOR_H
#define SQUID_ICAPINITIATOR_H

#include "AsyncCall.h"

/*
 * The ICAP Initiator is an ICAP vectoring point that initates ICAP
 * transactions. This interface exists to allow ICAP transactions to
 * signal their initiators that they are finished or aborted.
 */

class ICAPXaction;

class ICAPInitiator
{
public:
    virtual ~ICAPInitiator() {}

	virtual void noteIcapHeadersAdapted() = 0;
	virtual void noteIcapHeadersAborted() = 0;

	AsyncCallWrapper(93,4, ICAPInitiator, noteIcapHeadersAdapted);
	AsyncCallWrapper(93,3, ICAPInitiator, noteIcapHeadersAborted);
};

#endif /* SQUID_ICAPINITIATOR_H */
