/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLIP_H
#define SQUID_ACLIP_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "ip/Address.h"
#include "splay.h"

/// \ingroup ACLAPI
class acl_ip_data
{

public:
    MEMPROXY_CLASS(acl_ip_data);
    static acl_ip_data *FactoryParse(char const *);
    static int NetworkCompare(acl_ip_data * const & a, acl_ip_data * const &b);

    acl_ip_data ();

    acl_ip_data (Ip::Address const &, Ip::Address const &, Ip::Address const &, acl_ip_data *);
    void toStr(char *buf, int len) const;
    SBuf toSBuf() const;

    Ip::Address addr1;

    Ip::Address addr2;

    Ip::Address mask; /**< \todo This should perhapse be stored as a CIDR range now instead of a full IP mask. */

    acl_ip_data *next;      /**< used for parsing, not for storing */

private:

    static bool DecodeMask(const char *asc, Ip::Address &mask, int string_format_type);
};

MEMPROXY_CLASS_INLINE(acl_ip_data);

/// \ingroup ACLAPI
class ACLIP : public ACL
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    ACLIP() : data(NULL) {}
    explicit ACLIP(const ACLFlag flgs[]) : ACL(flgs), data(NULL) {}

    ~ACLIP();

    typedef Splay<acl_ip_data *> IPSplay;

    virtual char const *typeString() const = 0;
    virtual void parse();
    //    virtual bool isProxyAuth() const {return true;}
    virtual int match(ACLChecklist *checklist) = 0;
    virtual SBufList dump() const;
    virtual bool empty () const;

protected:

    int match(Ip::Address &);
    IPSplay *data;

};

#endif /* SQUID_ACLIP_H */

