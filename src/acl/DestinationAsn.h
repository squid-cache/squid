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

#ifndef SQUID_ACLDESTINATIONASN_H
#define SQUID_ACLDESTINATIONASN_H

#include "acl/Asn.h"
#include "acl/Strategy.h"
#include "ip/IpAddress.h"

/// \ingroup ACLAPI
class ACLDestinationASNStrategy : public ACLStrategy<IpAddress>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}

    static ACLDestinationASNStrategy *Instance();

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g++ warnings about
     * private constructors with no friends
     */
    ACLDestinationASNStrategy(ACLDestinationASNStrategy const &);

private:
    static ACLDestinationASNStrategy Instance_;
    ACLDestinationASNStrategy() {}

    ACLDestinationASNStrategy&operator=(ACLDestinationASNStrategy const &);
};

#endif /* SQUID_ACLDESTINATIONASN_H */
