/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLARP_H
#define SQUID_ACLARP_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "splay.h"

namespace Eui
{
class Eui48;
};

/// \ingroup ACLAPI
class ACLARP : public ACL
{
    MEMPROXY_CLASS(ACLARP);

public:
    ACLARP(char const *);
    ACLARP(ACLARP const &);
    ~ACLARP();
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
    Splay<Eui::Eui48 *> *data;
    char const *class_;
};

#endif /* SQUID_ACLARP_H */
