/*
 * $Id: stub_helper.cc,v 1.3 2007/05/07 19:54:58 wessels Exp $
 *
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Robert Collins
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

#include "squid.h"
#include "helper.h"

void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    fatal("Not implemented");
}

void
helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * lastserver)
{
    fatal("Not implemented");
}

void
helperStatefulFree(statefulhelper * hlp)
{
    fatal("Not implemented");
}

void
helperFree(helper * hlp)
{
    fatal("Not implemented");
}

CBDATA_TYPE(helper);

helper *
helperCreate(const char *name)
{
    helper *hlp;
    CBDATA_INIT_TYPE(helper);
    hlp = cbdataAlloc(helper);
    hlp->id_name = name;
    return hlp;
}

void
helperStats(StoreEntry * sentry, helper * hlp, const char *label)
{
    fatal("Not implemented");
}

void
helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp, const char *label)
{
    fatal("Not implemented");
}

void
helperShutdown(helper * hlp)
{
    fatal("Not implemented");
}

void
helperStatefulShutdown(statefulhelper * hlp)
{
    fatal("Not implemented");
}

void
helperOpenServers(helper * hlp)
{
    debugs(84,4,"Not implemented");
}

void
helperStatefulOpenServers(statefulhelper * hlp)
{
    debugs(84,4,"Not implemented");
}

void *
helperStatefulServerGetData(helper_stateful_server * srv)
{
    fatal("Not implemented");
    return NULL;
}

helper_stateful_server *
helperStatefulDefer(statefulhelper * hlp)
{
    fatal("Not implemented");
    return NULL;
}

void
helperStatefulReleaseServer(helper_stateful_server * srv)
{
    fatal("Not implemented");
}

CBDATA_TYPE(statefulhelper);

statefulhelper *
helperStatefulCreate(const char *name)
{
    statefulhelper *hlp;
    CBDATA_INIT_TYPE(statefulhelper);
    hlp = cbdataAlloc(statefulhelper);
    hlp->id_name = name;
    return hlp;
}

/*
 * DO NOT MODIFY:
 * arch-tag: 0b5fe2ac-1652-4b77-8788-85ded78ad3bb
 */
