/*
 * $Id: stub_access_log.cc,v 1.1 2006/04/18 12:46:13 robertc Exp $
 *
 * DEBUG: section 28    Access Control
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
#include "HierarchyLogEntry.h"


HierarchyLogEntry::HierarchyLogEntry()
{
    fatal("Not implemented.");
}

ping_data::ping_data() :
        n_sent(0),
        n_recv(0),
        n_replies_expected(0),
        timeout(0),
        timedout(0),
        w_rtt(0),
        p_rtt(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}
