
/*
 * $Id: ACL.h,v 1.6 2003/02/17 07:01:34 robertc Exp $
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

#ifndef SQUID_ACL_H
#define SQUID_ACL_H
#include "Array.h"

/* acl.c */
SQUIDCEXTERN int aclMatchAclList(const acl_list * list, ACLChecklist * checklist);
SQUIDCEXTERN void aclDestroyAccessList(acl_access **list);
SQUIDCEXTERN void aclDestroyAcls(acl **);
SQUIDCEXTERN void aclDestroyAclList(acl_list **);
SQUIDCEXTERN void aclParseAccessLine(acl_access **);
SQUIDCEXTERN void aclParseAclList(acl_list **);
SQUIDCEXTERN int aclIsProxyAuth(const char *name);
SQUIDCEXTERN err_type aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name);
SQUIDCEXTERN void aclParseDenyInfoLine(struct _acl_deny_info_list **);
SQUIDCEXTERN void aclDestroyDenyInfoList(struct _acl_deny_info_list **);
SQUIDCEXTERN void aclDestroyRegexList(struct _relist *data);
SQUIDCEXTERN int aclMatchRegex(relist * data, const char *word);
wordlist *aclDumpRegexList(relist * data);
SQUIDCEXTERN void aclParseRegexList(void *curlist);
SQUIDCEXTERN wordlist *aclDumpGeneric(const acl *);
SQUIDCEXTERN int aclPurgeMethodInUse(acl_access *);
SQUIDCEXTERN void aclCacheMatchFlush(dlink_list * cache);
extern void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);

class ACL {
  public:
    void *operator new(size_t);
    void operator delete(void *);
    virtual void deleteSelf() const;

    static ACL *Factory (char const *);
    static void ParseAclLine(acl ** head);
    static ACL* FindByName(const char *name);

    /* temporary until we subclass external acl's */
    static void ExternalAclLookup(ACLChecklist * ch, ACL *, EAH * callback, void *callback_data);

    ACL();
    ACL (squid_acl const);
    virtual ~ACL();
    virtual ACL *clone()const;
    virtual void parse();
    virtual char const *typeString() const;
    virtual squid_acl aclType() const { return type;}
    virtual bool isProxyAuth() const;
    virtual bool requiresRequest() const;
    virtual int match(ACLChecklist * checklist);
    virtual wordlist *dumpGeneric() const;
    virtual wordlist *dump() const;
    virtual bool valid () const;
    int checklistMatches(ACLChecklist *);
    
    /* only relevant to METHOD acl's */
    virtual bool containsPURGE() const;

    /* only relecant to ASN acl's */
    void startCache();
    
    int cacheMatchAcl(dlink_list * cache, ACLChecklist *);
    virtual int matchForCache(ACLChecklist *checklist);

    char name[ACL_NAME_SZ];
    char *cfgline;
    ACL *next;
  private:
    static MemPool *Pool;
    squid_acl type;
  protected:
    void *data;
  public:
    class Prototype {
      public:
	Prototype ();
	Prototype (ACL const *, char const *);
	~Prototype();
	static bool Registered(char const *);
	static ACL *Factory (char const *);
      private:
	ACL const*prototype;
	char const *typeString;
      private:
	static Vector<Prototype const *> * Registry;
	static void *Initialized;
	typedef Vector<Prototype const*>::iterator iterator;
	typedef Vector<Prototype const*>::const_iterator const_iterator;
	void registerMe();
    };
};

class acl_access {
  public:
    void *operator new(size_t);
    void operator delete(void *);
    virtual void deleteSelf() const;
    bool containsPURGE() const;
    allow_t allow;
    acl_list *aclList;
    char *cfgline;
    acl_access *next;
  private:
    CBDATA_CLASS(acl_access);
};

class ACLList {
  public:
    void *operator new(size_t);
    void operator delete(void *);
    virtual void deleteSelf() const;

    ACLList();
    void negated(bool isNegated);
    bool matches (ACLChecklist *)const;
    int op;
    acl *_acl;
    ACLList *next;
  private:
    static MemPool *Pool;
};

typedef ACLList acl_list;
#endif /* SQUID_ACL_H */
