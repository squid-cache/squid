
/*
 * $Id$
 */

#ifndef SQUID_ACLSSL_ERRORDATA_H
#define SQUID_ACLSSL_ERRORDATA_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "CbDataList.h"
#include "ssl/support.h"
#include "ssl/ErrorDetail.h"

class ACLSslErrorData : public ACLData<Ssl::error_t>
{

public:
    MEMPROXY_CLASS(ACLSslErrorData);

    ACLSslErrorData();
    ACLSslErrorData(ACLSslErrorData const &);
    ACLSslErrorData &operator= (ACLSslErrorData const &);
    virtual ~ACLSslErrorData();
    bool match(Ssl::error_t);
    wordlist *dump();
    void parse();
    bool empty() const;
    virtual ACLData<Ssl::error_t> *clone() const;

    CbDataList<Ssl::error_t> *values;
};

MEMPROXY_CLASS_INLINE(ACLSslErrorData);

#endif /* SQUID_ACLSSL_ERRORDATA_H */
