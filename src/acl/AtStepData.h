/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLATSTEPDATA_H
#define SQUID_ACLATSTEPDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "enums.h"
#include <list>

class ACLAtStepData : public ACLData<XactionSteps>
{
    MEMPROXY_CLASS(ACLAtStepData);

public:
    ACLAtStepData();
    ACLAtStepData(ACLAtStepData const &);
    ACLAtStepData &operator= (ACLAtStepData const &);
    virtual ~ACLAtStepData();
    bool match(XactionSteps);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLAtStepData *clone() const;

    static const char *AtStepStr(XactionSteps);
    static XactionSteps AtStep(const char *);

    std::list<XactionSteps> values;

private:
    static const char *AtStepValuesStr[];
};

#endif /* SQUID_ACLSSL_ERRORDATA_H */

