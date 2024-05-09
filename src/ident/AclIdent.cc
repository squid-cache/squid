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
    if (const auto lookup = checklist->identLookup()) {
        if (const auto &ident = *lookup)
            return data->match(SBuf(*ident).c_str());
        else
            return data->match(dash_str);
    } else if (checklist->conn() != nullptr && Comm::IsConnOpen(checklist->conn()->clientConnection)) {
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

