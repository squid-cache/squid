/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPSTATUS_H
#define SQUID_ACLHTTPSTATUS_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "splay.h"

/// \ingroup ACLAPI
struct acl_httpstatus_data {
    int status1, status2;
    acl_httpstatus_data(int);
    acl_httpstatus_data(int, int);
    SBuf toStr() const; // was toStr

    static int compare(acl_httpstatus_data* const& a, acl_httpstatus_data* const& b);
};

/// \ingroup ACLAPI
class ACLHTTPStatus : public ACL
{
    MEMPROXY_CLASS(ACLHTTPStatus);

public:
    ACLHTTPStatus(char const *);
    ACLHTTPStatus(ACLHTTPStatus const &);
    ~ACLHTTPStatus();
    ACLHTTPStatus&operator=(ACLHTTPStatus const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual bool requiresReply() const { return true; }

protected:
    Splay<acl_httpstatus_data*> *data;
    char const *class_;
};

#endif /* SQUID_ACLHTTPSTATUS_H */

