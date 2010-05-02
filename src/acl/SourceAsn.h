/*
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
#ifndef SQUID_ACLSOURCEASN_H
#define SQUID_ACLSOURCEASN_H

#if 0
#include "acl/Asn.h"
#endif

class ACLChecklist;

#include "acl/Strategy.h"
#include "ip/Address.h"

class ACLSourceASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    static ACLSourceASNStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSourceASNStrategy(ACLSourceASNStrategy const &);

private:
    static ACLSourceASNStrategy Instance_;
    ACLSourceASNStrategy() {}

    ACLSourceASNStrategy&operator=(ACLSourceASNStrategy const &);
};

#endif /* SQUID_ACLSOURCEASN_H */
