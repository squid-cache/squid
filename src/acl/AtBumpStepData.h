#ifndef SQUID_ACLATSTEPDATA_H
#define SQUID_ACLATSTEPDATA_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "CbDataList.h"
#include "ssl/support.h"
#include <list>

class ACLAtStepData : public ACLData<Ssl::BumpStep>
{

public:
    MEMPROXY_CLASS(ACLAtStepData);

    ACLAtStepData();
    ACLAtStepData(ACLAtStepData const &);
    ACLAtStepData &operator= (ACLAtStepData const &);
    virtual ~ACLAtStepData();
    bool match(Ssl::BumpStep);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual  ACLAtStepData *clone() const;

    std::list<Ssl::BumpStep> values;
};

MEMPROXY_CLASS_INLINE(ACLAtStepData);

#endif /* SQUID_ACLSSL_ERRORDATA_H */
