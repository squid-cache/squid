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
#include "acl/ExtUser.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
#include "HttpRequest.h"

ACLExtUser::~ACLExtUser()
{
    delete data;
}

ACLExtUser::ACLExtUser(ACLData<char const *> *newData, char const *newType) : data (newData), type_ (newType) {}

ACLExtUser::ACLExtUser (ACLExtUser const &old) : data (old.data->clone()), type_ (old.type_)
{}

ACLExtUser &
ACLExtUser::operator= (ACLExtUser const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLExtUser::typeString() const
{
    return type_;
}

void
ACLExtUser::parse()
{
    debugs(28, 3, "aclParseUserList: current is null. Creating");
    data = new ACLUserData;
    data->parse();
}

int
ACLExtUser::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    if (checklist->request->extacl_user.size()) {
        return data->match(checklist->request->extacl_user.termedBuf());
    } else {
        return -1;
    }
}

wordlist *
ACLExtUser::dump() const
{
    return data->dump();
}

bool
ACLExtUser::empty () const
{
    return data->empty();
}

ACL *
ACLExtUser::clone() const
{
    return new ACLExtUser(*this);
}

