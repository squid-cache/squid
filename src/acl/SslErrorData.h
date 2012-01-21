
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
#include <vector>

class ACLSslErrorData : public ACLData<Ssl::Errors const&>
{

public:
    MEMPROXY_CLASS(ACLSslErrorData);

    ACLSslErrorData();
    ACLSslErrorData(ACLSslErrorData const &);
    ACLSslErrorData &operator= (ACLSslErrorData const &);
    virtual ~ACLSslErrorData();
    bool match(Ssl::Errors const &);
    wordlist *dump();
    void parse();
    bool empty() const;
    virtual  ACLSslErrorData *clone() const;

    CbDataList<Ssl::ssl_error_t> *values;
};

MEMPROXY_CLASS_INLINE(ACLSslErrorData);

#endif /* SQUID_ACLSSL_ERRORDATA_H */
