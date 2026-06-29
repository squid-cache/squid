/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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

// XXX: fix this copying for net-snmp struct members:
//   struct snmp_session *subsession;
//   struct snmp_session *next;
//   void *callback_magic;
//   .. SNMPv3 members
//   oid *securityAuthProto;
//   u_char *securityAuthLocalKey;
//   oid *securityPrivProto;
//   u_char *securityPrivLocalKey;
//   char *paramName;
//   netsnmp_trap_stats *trap_stats; // #if !defined(NETSNMP_NO_TRAP_STATS)
//   void *securityInfo;
//   struct netsnmp_container_s *transport_configuration;
//   oid *myvoid;
//   struct usmUser *sessUser;
// see https://github.com/net-snmp/net-snmp/blob/fb7534d9/include/net-snmp/types.h#L294-L415

    memcpy(static_cast<snmp_session *>(this), &session, sizeof(snmp_session));
    // memcpy did a shallow copy, make sure we have our own allocations
    if (session.community) {
        community = (u_char*)xstrdup((char*)session.community);
    }
    if (session.peername) {
        peername = xstrdup(session.peername);
    }
    if (session.localname) {
        localname = xstrdup(session.localname);
    }
    return *this;
}

void
Snmp::Session::reset()
{
    xfree(peername);
    xfree(localname);
    if (community_len > 0) {
        Must(community != nullptr);
        xfree(community);
    }
    memset(static_cast<snmp_session *>(this), 0, sizeof(snmp_session));

    // XXX: fix this as well for above listed net-snmp pointer members
}

void
Snmp::Session::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putPod(version);
    msg.putPod(retries);
    msg.putPod(timeout);
    msg.putPod(flags);
    int len = (peername ? strlen(peername) : 0);
    msg.putInt(len);
    if (len > 0)
        msg.putFixed(peername, len);
    msg.putPod(remote_port);
    len = (localname ? strlen(localname) : 0);
    msg.putInt(len);
    if (len > 0)
        msg.putFixed(localname, len);
    msg.putPod(local_port);
    msg.putInt(community_len);
    if (community_len > 0) {
        Must(community != nullptr);
        msg.putFixed(community, community_len);
    }
    msg.putPod(rcvMsgMaxSize);
    msg.putPod(sndMsgMaxSize);

    // XXX: fix this as well for above listed net-snmp pointer members
}

void
Snmp::Session::unpack(const Ipc::TypedMsgHdr& msg)
{
    reset();
    msg.getPod(version);
    msg.getPod(retries);
    msg.getPod(timeout);
    msg.getPod(flags);
    int len = msg.getInt();
    if (len > 0) {
        peername = static_cast<char*>(xmalloc(len + 1));
        Must(peername != nullptr);
        msg.getFixed(peername, len);
        peername[len] = 0;
    }
    msg.getPod(remote_port);
    len = msg.getInt();
    if (len > 0) {
        localname = static_cast<char*>(xmalloc(len + 1));
        Must(localname != nullptr);
        msg.getFixed(localname, len);
        localname[len] = 0;
    }
    msg.getPod(local_port);
    community_len = msg.getInt();
    if (community_len > 0) {
        community = static_cast<u_char*>(xmalloc(community_len + 1));
        Must(community != nullptr);
        msg.getFixed(community, community_len);
        community[community_len] = 0;
    }
    msg.getPod(rcvMsgMaxSize);
    msg.getPod(sndMsgMaxSize);
}

