#ifndef SQUID_ACLHIERCODEDATA_H
#define SQUID_ACLHIERCODEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "CbDataList.h"
#include "hier_code.h"

/// \ingroup ACLAPI
class ACLHierCodeData : public ACLData<hier_code>
{

public:
    MEMPROXY_CLASS(ACLHierCodeData);

    ACLHierCodeData();
    ACLHierCodeData(ACLHierCodeData const &);
    ACLHierCodeData &operator= (ACLHierCodeData const &);
    virtual ~ACLHierCodeData();
    bool match(hier_code);
    wordlist *dump();
    void parse();
    bool empty() const;
    virtual ACLData<hier_code> *clone() const;

    // mask of codes this ACL might match.
    bool values[HIER_MAX];
};

MEMPROXY_CLASS_INLINE(ACLHierCodeData);

#endif /* SQUID_ACLHIERCODEDATA_H */
