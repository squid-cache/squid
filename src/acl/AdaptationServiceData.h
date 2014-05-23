
#ifndef SQUID_ADAPTATIONSERVICEDATA_H
#define SQUID_ADAPTATIONSERVICEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/StringData.h"

/// \ingroup ACLAPI
class ACLAdaptationServiceData : public ACLStringData
{
public:
    ACLAdaptationServiceData() : ACLStringData() {}
    ACLAdaptationServiceData(ACLAdaptationServiceData const &old) : ACLStringData(old) {};
    // Not implemented
    ACLAdaptationServiceData &operator= (ACLAdaptationServiceData const &);
    virtual void parse();
    virtual ACLData<char const *> *clone() const;
};

#endif /* SQUID_ADAPTATIONSERVICEDATA_H */
