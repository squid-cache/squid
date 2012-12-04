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

#ifndef SQUID_ACL_RANDOM_H
#define SQUID_ACL_RANDOM_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

/// \ingroup ACLAPI
class ACLRandom : public ACL
{

public:
    MEMPROXY_CLASS(ACLRandom);

    ACLRandom(char const *);
    ACLRandom(ACLRandom const &);
    ~ACLRandom();
    ACLRandom&operator=(ACLRandom const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual wordlist *dump() const;
    virtual bool empty () const;
    virtual bool valid() const;

protected:
    static Prototype RegistryProtoype;
    static ACLRandom RegistryEntry_;
    double data;        // value to be exceeded before this ACL will match
    char pattern[256];  // pattern from config file. Used to generate 'data'
    char const *class_;
};

MEMPROXY_CLASS_INLINE(ACLRandom);

#endif /* SQUID_ACL_RANDOM_H */
