/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLARP_H
#define SQUID_ACLARP_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

#include <set>

namespace Eui
{
class Eui48;
};

/// \ingroup ACLAPI
class ACLARP : public ACL
{

public:
    MEMPROXY_CLASS(ACLARP);

    ACLARP(char const *);
    ACLARP(ACLARP const &);
    ~ACLARP() {}
    ACLARP&operator=(ACLARP const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;

protected:
    static Prototype RegistryProtoype;
    static ACLARP RegistryEntry_;
    char const *class_;
    typedef std::set<Eui::Eui48> AclArpData_t;
    AclArpData_t aclArpData;
};

MEMPROXY_CLASS_INLINE(ACLARP);

#endif /* SQUID_ACLARP_H */

