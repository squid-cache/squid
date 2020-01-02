/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Session.h"
#include "tools.h"

Snmp::Session::Session()
{
    memset(static_cast<snmp_session *>(this), 0, sizeof(snmp_session));
}

Snmp::Session::Session(const Snmp::Session& session) : Session()
{
    operator =(session);
}

Snmp::Session&
Snmp::Session::operator = (const Session& session)
{
    if (&session == this)
        return *this;

    reset();
    memcpy(static_cast<snmp_session *>(this), &session, sizeof(snmp_session));
    // memcpy did a shallow copy, make sure we have our own allocations
    if (session.community) {
        community = (u_char*)xstrdup((char*)session.community);
    }
    if (session.peername) {
        peername = xstrdup(session.peername);
    }
    return *this;
}

void
Snmp::Session::reset()
{
    if (community_len > 0) {
        Must(community != NULL);
        xfree(community);
    }
    xfree(peername);
    memset(static_cast<snmp_session *>(this), 0, sizeof(snmp_session));
}

void
Snmp::Session::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putPod(Version);
    msg.putInt(community_len);
    if (community_len > 0) {
        Must(community != NULL);
        msg.putFixed(community, community_len);
    }
    msg.putPod(retries);
    msg.putPod(timeout);
    int len = peername != NULL ? strlen(peername) : 0;
    msg.putInt(len);
    if (len > 0)
        msg.putFixed(peername, len);
    msg.putPod(remote_port);
    msg.putPod(local_port);
}

void
Snmp::Session::unpack(const Ipc::TypedMsgHdr& msg)
{
    reset();
    msg.getPod(Version);
    community_len = msg.getInt();
    if (community_len > 0) {
        community = static_cast<u_char*>(xmalloc(community_len + 1));
        Must(community != NULL);
        msg.getFixed(community, community_len);
        community[community_len] = 0;
    }
    msg.getPod(retries);
    msg.getPod(timeout);
    int len = msg.getInt();
    if (len > 0) {
        peername = static_cast<char*>(xmalloc(len + 1));
        Must(peername != NULL);
        msg.getFixed(peername, len);
        peername[len] = 0;
    }
    msg.getPod(remote_port);
    msg.getPod(local_port);
}

