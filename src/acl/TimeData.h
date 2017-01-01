/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTIMEDATA_H
#define SQUID_ACLTIMEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "splay.h"

class ACLTimeData : public ACLData<time_t>
{
    MEMPROXY_CLASS(ACLTimeData);

public:
    ACLTimeData();
    ACLTimeData(ACLTimeData const &);
    ACLTimeData&operator=(ACLTimeData const &);
    virtual ~ACLTimeData();
    bool match(time_t);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<time_t> *clone() const;

private:
    int weekbits;
    int start;
    int stop;
    ACLTimeData *next;
};

#endif /* SQUID_ACLTIMEDATA_H */

