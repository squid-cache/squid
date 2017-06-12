/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_IDENT

#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "globals.h"
#include "http/Stream.h"
#include "ident/AclIdent.h"
#include "ident/Ident.h"

ACLIdent::~ACLIdent()
{
    delete data;
}

ACLIdent::ACLIdent(ACLData<char const *> *newData, char const *newType) : data (newData), type_ (newType) {}

ACLIdent::ACLIdent (ACLIdent const &old) : data (old.data->clone()), type_ (old.type_)
{}

ACLIdent &
ACLIdent::operator= (ACLIdent const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLIdent::typeString() const
{
    return type_;
}

void
ACLIdent::parseFlags()
{
    ParseFlags(Acl::NoOptions(), data->supportedFlags());
}

void
ACLIdent::parse()
{
    if (!data) {
        debugs(28, 3, HERE << "current is null. Creating");
        data = new ACLUserData;
    }

    data->parse();
}

int
ACLIdent::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    if (checklist->rfc931[0]) {
        return data->match(checklist->rfc931);
    } else if (checklist->conn() != NULL && checklist->conn()->clientConnection != NULL && checklist->conn()->clientConnection->rfc931[0]) {
        return data->match(checklist->conn()->clientConnection->rfc931);
    } else if (checklist->conn() != NULL && Comm::IsConnOpen(checklist->conn()->clientConnection)) {
        if (checklist->goAsync(IdentLookup::Instance())) {
            debugs(28, 3, "switching to ident lookup state");
            return -1;
        }
        // else fall through to ACCESS_DUNNO failure below
    } else {
        debugs(28, DBG_IMPORTANT, HERE << "Can't start ident lookup. No client connection" );
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

ACL *
ACLIdent::clone() const
{
    return new ACLIdent(*this);
}

IdentLookup IdentLookup::instance_;

IdentLookup *
IdentLookup::Instance()
{
    return &instance_;
}

void
IdentLookup::checkForAsync(ACLChecklist *cl)const
{
    ACLFilledChecklist *checklist = Filled(cl);
    const ConnStateData *conn = checklist->conn();
    // check that ACLIdent::match() tested this lookup precondition
    assert(conn && Comm::IsConnOpen(conn->clientConnection));
    debugs(28, 3, HERE << "Doing ident lookup" );
    Ident::Start(checklist->conn()->clientConnection, LookupDone, checklist);
}

void
IdentLookup::LookupDone(const char *ident, void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    if (ident) {
        xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);
    } else {
        xstrncpy(checklist->rfc931, dash_str, USER_IDENT_SZ);
    }

    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    if (checklist->conn() != NULL && checklist->conn()->clientConnection != NULL && !checklist->conn()->clientConnection->rfc931[0])
        xstrncpy(checklist->conn()->clientConnection->rfc931, checklist->rfc931, USER_IDENT_SZ);

    checklist->resumeNonBlockingCheck(IdentLookup::Instance());
}

#endif /* USE_IDENT */

