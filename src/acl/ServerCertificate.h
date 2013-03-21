/*
 */

#ifndef SQUID_ACLSERVERCERTIFICATE_H
#define SQUID_ACLSERVERCERTIFICATE_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Checklist.h"
#include "ssl/support.h"
#include "acl/Strategised.h"

/// \ingroup ACLAPI
class ACLServerCertificateStrategy : public ACLStrategy<X509 *>
{
public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLServerCertificateStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLServerCertificateStrategy(ACLServerCertificateStrategy const &);

private:
    static ACLServerCertificateStrategy Instance_;
    ACLServerCertificateStrategy() {}

    ACLServerCertificateStrategy&operator=(ACLServerCertificateStrategy const &);
};

/// \ingroup ACLAPI
class ACLServerCertificate
{
private:
    static ACL::Prototype X509FingerprintRegistryProtoype;
    static ACLStrategised<X509*> X509FingerprintRegistryEntry_;
};

#endif /* SQUID_ACLSERVERCERTIFICATE_H */
