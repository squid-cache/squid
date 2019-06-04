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
#include <list>

class ACLAtStepData : public ACLData<int>
{
    MEMPROXY_CLASS(ACLAtStepData);

public:
    enum AtStepValues {
#if USE_OPENSSL
        atStepSslBump1,
        atStepSslBump2,
        atStepSslBump3,
#endif
        atStepGeneratingConnect,
        atStepValuesEnd
    };

    ACLAtStepData();
    ACLAtStepData(ACLAtStepData const &);
    ACLAtStepData &operator= (ACLAtStepData const &);
    virtual ~ACLAtStepData();
    bool match(int);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLAtStepData *clone() const;

    static const char *AtStepStr(int);
    static int AtStep(const char *);

    std::list<int> values;

private:
    static const char *AtStepValuesStr[];
};

#endif /* SQUID_ACLSSL_ERRORDATA_H */

