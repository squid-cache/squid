/*
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "cbdata.h"
#include "PingData.h"
#include "ip/IpAddress.h"

class ps_state
{

public:
    void *operator new(size_t);
    ps_state();
    HttpRequest *request;
    StoreEntry *entry;
    int always_direct;
    int never_direct;
    int direct;
    PSC *callback;
    void *callback_data;
    FwdServer *servers;
    /*
     * Why are these IpAddress instead of peer *?  Because a
     * peer structure can become invalid during the peer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the peer * based on the address when we are finally ready to
     * reference the peer structure.
     */

    IpAddress first_parent_miss;

    IpAddress closest_parent_miss;
    /*
     * ->hit can be peer* because it should only be
     * accessed during the thread when it is set
     */
    peer *hit;
    peer_t hit_type;
    ping_data ping;
    ACLChecklist *acl_checklist;
private:
    CBDATA_CLASS(ps_state);
};


#endif /* SQUID_PEERSELECTSTATE_H */
