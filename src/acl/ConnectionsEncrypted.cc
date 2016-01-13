/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ConnectionsEncrypted.h"
#include "acl/FilledChecklist.h"
#include "Debug.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"

ACL *
Acl::ConnectionsEncrypted::clone() const
{
    return new Acl::ConnectionsEncrypted(*this);
}

Acl::ConnectionsEncrypted::ConnectionsEncrypted (char const *theClass) : class_ (theClass)
{}

Acl::ConnectionsEncrypted::ConnectionsEncrypted (Acl::ConnectionsEncrypted const & old) :class_ (old.class_)
{}

Acl::ConnectionsEncrypted::~ConnectionsEncrypted()
{}

char const *
Acl::ConnectionsEncrypted::typeString() const
{
    return class_;
}

bool
Acl::ConnectionsEncrypted::empty () const
{
    return false;
}

void
Acl::ConnectionsEncrypted::parse()
{
    if (ConfigParser::strtokFile()) {
        debugs(89, DBG_CRITICAL, "WARNING: connections_encrypted does not accepts any value.");
    }
}

int
Acl::ConnectionsEncrypted::match(ACLChecklist *checklist)
{
    if (!checklist->hasRequest()) {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL is used in " <<
               "context without an HTTP request. Assuming mismatch.");
        return 0;
    }

    ACLFilledChecklist *filled = Filled((ACLChecklist*)checklist);

    const bool safeRequest =
        !(filled->request->sources & HttpMsg::srcUnsafe);
    const bool safeReply = !filled->reply ||
                           !(filled->reply->sources & HttpMsg::srcUnsafe);

    return (safeRequest && safeReply) ? 1 : 0;
}

SBufList
Acl::ConnectionsEncrypted::dump() const
{
    return SBufList();
}

