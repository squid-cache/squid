/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#if USE_IDENT

#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
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
    } else if (checklist->conn() != NULL && checklist->conn()->rfc931[0]) {
        return data->match(checklist->conn()->rfc931);
    } else {
        debugs(28, 3, HERE << "switching to ident lookup state");
        checklist->changeState(IdentLookup::Instance());
        return 0;
    }
}

wordlist *
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
    if (checklist->conn() != NULL) {
        debugs(28, 3, HERE << "Doing ident lookup" );
        checklist->asyncInProgress(true);
        Ident::Start(checklist->conn()->me, checklist->conn()->peer, LookupDone, checklist);
    } else {
        debugs(28, DBG_IMPORTANT, "IdentLookup::checkForAsync: Can't start ident lookup. No client connection" );
        checklist->currentAnswer(ACCESS_DENIED);
        checklist->markFinished();
    }
}

void
IdentLookup::LookupDone(const char *ident, void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    assert(checklist->asyncState() == IdentLookup::Instance());

    if (ident) {
        xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);
    } else {
        xstrncpy(checklist->rfc931, dash_str, USER_IDENT_SZ);
    }

    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    if (checklist->conn() != NULL && !checklist->conn()->rfc931[0])
        xstrncpy(checklist->conn()->rfc931, checklist->rfc931, USER_IDENT_SZ);

    checklist->asyncInProgress(false);
    checklist->changeState(ACLChecklist::NullState::Instance());
    checklist->check();
}

#endif /* USE_IDENT */
