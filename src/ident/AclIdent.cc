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
    if (const auto lookup = checklist->clientIdentLookup()) {
        if (const auto &ident = *lookup)
            return data->match(SBuf(*ident).c_str()); // XXX: performance regression, c_str() may reallocate
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
    if (const auto c = ch.acceptedConnection()) {
        const auto &clientConnection = *c;

        // check this before checking isOpen() for more informative debugging
        if (clientConnection.identLookup) {
            debugs(82, 7, "no; already attempted");
            return false;
        }

        if (!clientConnection.isOpen()) {
            debugs(82, 5, "no; client connection closed: " << clientConnection.id);
            return false;
        }

        debugs(82, 7, "yes for " << clientConnection.id);
        return true;
    }

    debugs(82, 5, "no; not a client-associated transaction or insufficient client info");
    return false;
}

void
ACLIdent::StartLookup(ACLFilledChecklist &cl, const Acl::Node &)
{
    const auto clientConnection = cl.acceptedConnection();
    assert(clientConnection);
    assert(Comm::IsConnOpen(clientConnection)); // TODO: Remove as unused/unnecessary
    debugs(28, 3, "Doing ident lookup" );
    Ident::Start(clientConnection, LookupDone, &cl);
}

void
ACLIdent::LookupDone(const Ident::Lookup &ident, void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    if (const auto mgr = checklist->conn()) {
        if (const auto &c = mgr->clientConnection)
            c->updateIdent(ident);
    }

    checklist->resumeNonBlockingCheck();
}

