/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */


#ifndef SQUID_ACLCONNMARK_H
#define SQUID_ACLCONNMARK_H

#include "acl/Acl.h"
#include "map"

class ACLConnMark : public ACL
{
    MEMPROXY_CLASS(ACLConnMark);

public:
    ACLConnMark();
    ACLConnMark&operator=(ACLConnMark const &);

    virtual ACL *clone() const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty() const;

protected:
    std::map<uint32_t, uint32_t> marks;
};

#endif /* SQUID_ACLCONNMARK_H */
