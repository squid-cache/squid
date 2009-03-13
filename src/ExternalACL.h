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
#ifndef SQUID_EXTERNALACL_H
#define SQUID_EXTERNALACL_H

#include "acl/Checklist.h"

class external_acl;

class ExternalACLLookup : public ACLChecklist::AsyncState
{

public:
    static ExternalACLLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static ExternalACLLookup instance_;
    static void LookupDone(void *data, void *result);
};

/** \todo CLEANUP: kill this typedef. */
typedef struct _external_acl_data external_acl_data;

#include "acl/Acl.h"

class ACLExternal : public ACL
{

public:
    MEMPROXY_CLASS(ACLExternal);

    static void ExternalAclLookup(ACLChecklist * ch, ACLExternal *, EAH * callback, void *callback_data);


    ACLExternal(char const *);
    ACLExternal(ACLExternal const &);
    ~ACLExternal();
    ACLExternal&operator=(ACLExternal const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    /* This really should be dynamic based on the external class defn */
    virtual bool requiresRequest() const {return true;}

    /* when requiresRequest is made dynamic, review this too */
    //    virtual bool requiresReply() const {return true;}
    virtual bool isProxyAuth() const;
    virtual wordlist *dump() const;
    virtual bool valid () const;
    virtual bool empty () const;

protected:
    static Prototype RegistryProtoype;
    static ACLExternal RegistryEntry_;
    external_acl_data *data;
    char const *class_;
};

MEMPROXY_CLASS_INLINE(ACLExternal);

#endif /* SQUID_EXTERNALACL_H */
