/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTIMEDATA_H
#define SQUID_ACLTIMEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"

class ACLTimeData : public ACLData<time_t>
{
    MEMPROXY_CLASS(ACLTimeData);

public:
    ACLTimeData();
    virtual ~ACLTimeData();
    bool match(time_t);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;

private:
    int weekbits;
    int start;
    int stop;
    ACLTimeData *next;
};

#endif /* SQUID_ACLTIMEDATA_H */

