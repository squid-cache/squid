
/*
 * $Id: ACLASN.h,v 1.4 2003/08/04 22:14:38 robertc Exp $
 *
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

#ifndef SQUID_ACLASN_H
#define SQUID_ACLASN_H
#include "ACLData.h"
#include "List.h"
#include "ACLStrategised.h"
#include "ACLChecklist.h"

SQUIDCEXTERN int asnMatchIp(List<int> *, struct in_addr);
SQUIDCEXTERN void asnInit(void);
SQUIDCEXTERN void asnFreeMemory(void);

class ACLASN : public ACLData<struct in_addr>
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    virtual ~ACLASN();

    virtual bool match(struct in_addr);
    virtual wordlist *dump();
    virtual void parse();
    virtual ACLData<struct in_addr> *clone() const;
    virtual void prepareForUse();

private:
    static MemPool *Pool;
    static ACL::Prototype SourceRegistryProtoype;
    static ACLStrategised<struct in_addr> SourceRegistryEntry_;
    static ACL::Prototype DestinationRegistryProtoype;
    static ACLStrategised<struct in_addr> DestinationRegistryEntry_;
    List<int> *data;
};

#endif /* SQUID_ACLASN_H */
