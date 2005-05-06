
/*
 * $Id$
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

#ifndef SQUID_ACLPROXYAUTH_H
#define SQUID_ACLPROXYAUTH_H
#include "ACL.h"
#include "ACLData.h"
#include "ACLChecklist.h"

class ProxyAuthLookup : public ACLChecklist::AsyncState
{

public:
    static ProxyAuthLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static ProxyAuthLookup instance_;
    static void LookupDone(void *data, char *result);
};

class ProxyAuthNeeded : public ACLChecklist::AsyncState
{

public:
    static ProxyAuthNeeded *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static ProxyAuthNeeded instance_;
};

class ACLProxyAuth : public ACL
{

public:
    MEMPROXY_CLASS(ACLProxyAuth);

    ~ACLProxyAuth();
    ACLProxyAuth(ACLData<char const *> *, char const *);
    ACLProxyAuth (ACLProxyAuth const &);
    ACLProxyAuth &operator= (ACLProxyAuth const &);

    virtual char const *typeString() const;
    virtual void parse();
    virtual bool isProxyAuth() const {return true;}

    virtual int match(ACLChecklist *checklist);
    virtual wordlist *dump() const;
    virtual bool valid () const;
    virtual bool empty () const;
    virtual bool requiresRequest() const {return true;}

    virtual ACL *clone()const;
    virtual int matchForCache(ACLChecklist *checklist);

private:
    static Prototype UserRegistryProtoype;
    static ACLProxyAuth UserRegistryEntry_;
    static Prototype RegexRegistryProtoype;
    static ACLProxyAuth RegexRegistryEntry_;
    int matchProxyAuth(ACLChecklist *);
    void checkAuthForCaching(ACLChecklist *) const;
    ACLData<char const *> *data;
    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLProxyAuth)

#endif /* SQUID_ACLPROXYAUTH_H */
