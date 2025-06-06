/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_TIMEDATA_H
#define SQUID_SRC_ACL_TIMEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"

class ACLTimeData : public ACLData<time_t>
{
    MEMPROXY_CLASS(ACLTimeData);

public:
    ACLTimeData();
    ~ACLTimeData() override;
    bool match(time_t) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    int weekbits;
    int start;
    int stop;
    ACLTimeData *next;
};

#endif /* SQUID_SRC_ACL_TIMEDATA_H */

