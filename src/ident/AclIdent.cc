/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "globals.h"
#include "http/Stream.h"
#include "ident/AclIdent.h"

ACLIdent::~ACLIdent()
{
    delete data;
}

ACLIdent::ACLIdent(ACLData<char const *> *newData, char const *newType) : data (newData), type_ (newType) {}

char const *
ACLIdent::typeString() const
{
    return type_;
}

const Acl::Options &
ACLIdent::lineOptions()
{
    return data->lineOptions();
}

void
ACLIdent::parse()
{
    if (!data) {
        debugs(28, 3, "current is null. Creating");
        data = new ACLUserData;
    }

    data->parse();
}

int
ACLIdent::match(ACLChecklist *cl)
{
    const auto checklist = Filled(cl);
    // XXX: checklist->identLookup() uses ALE but our ACLIdent::requiresAle() is
    // false. We may silently goAsync() again if a buggy caller forgot to set
    // ALE but did set checklist->conn(). Or we may mislead about our inability
    // to start lookup if a buggy caller set neither while forgotten ALE had
    // Ident::Lookup information.
    //
    // Moreover, IdentStateData (i.e. lookup code) does not use ALE to store
    // Ident lookup result; it uses ACLFilledChecklist::conn()->clientConnection
    // instead. Thus, this match() code checks one data member but fill another.
    // This "disconnect" was created by branch commit 6c2106d4 that removed
    // conn() checking from ACLFilledChecklist::rfc931(). I do not know why.
    if (const auto lookup = checklist->identLookup()) {
        if (const auto &ident = *lookup)
            return data->match(SBuf(*ident).c_str());
        else
            return data->match(dash_str);
    } else if (ShouldStartLookup(*checklist)) {
        if (checklist->goAsync(StartLookup, *this)) {
            debugs(28, 3, "switching to ident lookup state");
            return -1;
        }
        // else fall through to ACCESS_DUNNO failure below
    } else {
        debugs(28, DBG_IMPORTANT, "ERROR: Cannot start ident lookup. No client connection" );
        // fall through to ACCESS_DUNNO failure below
    }

    checklist->markFinished(ACCESS_DUNNO, "cannot start ident lookup");
    return -1;
}

SBufList
ACLIdent::dump() const
{
    return data->dump();
}

bool
ACLIdent::empty () const
{
    return data->empty();
}

bool
ACLIdent::ShouldStartLookup(const ACLFilledChecklist &ch)
{
    if (const auto mgr = ch.conn()) {
        if (!mgr->clientConnection) {
            debugs(82, 7, "no; lack client connection info");
            return false;
        }

        const auto &clientConnection = *mgr->clientConnection;

        // check this before checking isOpen() for more informative debugging
        if (clientConnection.identLookup) {
            debugs(82, 7, "no; already attempted");
            return false;
        }

        if (!clientConnection.isOpen()) {
            debugs(82, 5, "no; client connection closed: " << mgr->clientConnection->id);
            return false;
        }

        debugs(82, 7, "yes for " << mgr->clientConnection->id);
        return true;
    }

    debugs(82, 5, "no; not a client-associated transaction or client gone");
    return false;
}

void
ACLIdent::StartLookup(ACLFilledChecklist &cl, const Acl::Node &)
{
    const ConnStateData *conn = cl.conn();
    // check that ACLIdent::match() tested this lookup precondition
    assert(conn && Comm::IsConnOpen(conn->clientConnection));
    debugs(28, 3, "Doing ident lookup" );
    Ident::Start(cl.conn()->clientConnection, LookupDone, &cl);
}

void
ACLIdent::LookupDone(const Ident::Lookup &ident, void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    const auto conn = checklist->conn();
    if (conn && conn->clientConnection)
        conn->clientConnection->setIdent(ident);
    checklist->resumeNonBlockingCheck();
}

