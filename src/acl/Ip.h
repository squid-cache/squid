/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

class acl_ip_data
{
    MEMPROXY_CLASS(acl_ip_data);

public:
    static acl_ip_data *FactoryParse(char const *);
    static int NetworkCompare(acl_ip_data * const & a, acl_ip_data * const &b);

    acl_ip_data ();

    acl_ip_data (Ip::Address const &, Ip::Address const &, Ip::Address const &, acl_ip_data *);
    void toStr(char *buf, int len) const;
    SBuf toSBuf() const;

    Ip::Address addr1;

    Ip::Address addr2;

    Ip::Address mask; // TODO: should use a CIDR range

    acl_ip_data *next;      /**< used for parsing, not for storing */

private:

    static bool DecodeMask(const char *asc, Ip::Address &mask, int string_format_type);
};

class ACLIP : public ACL
{
public:
    void *operator new(size_t);
    void operator delete(void *);

    ACLIP() : data(nullptr) {}
    ~ACLIP() override;

    typedef Splay<acl_ip_data *> IPSplay;

    char const *typeString() const override = 0;
    void parse() override;
    //    virtual bool isProxyAuth() const {return true;}
    int match(ACLChecklist *checklist) override = 0;
    SBufList dump() const override;
    bool empty () const override;

protected:

    int match(const Ip::Address &);
    IPSplay *data;

};

#endif /* SQUID_ACLIP_H */

