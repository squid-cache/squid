/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSTRINGDATA_H
#define SQUID_ACLSTRINGDATA_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "SBuf.h"

#include <set>

class ACLStringData : public ACLData<char const *>
{

public:
    MEMPROXY_CLASS(ACLStringData);

    ACLStringData() {}
    ACLStringData(ACLStringData const &);
    ACLStringData &operator= (ACLStringData const &);
    virtual ~ACLStringData() {}
    bool match(char const *);
    virtual SBufList dump() const;
    virtual void parse();
    bool empty() const;
    virtual ACLData<char const *> *clone() const;
    /// Insert a string data value
    void insert(const char *);

private:
    typedef std::set<SBuf> StringValues_t;
    StringValues_t stringValues;
};

/* TODO move into .cci files */

MEMPROXY_CLASS_INLINE(ACLStringData);

#endif /* SQUID_ACLSTRINGDATA_H */

