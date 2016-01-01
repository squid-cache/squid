/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCERTIFICATE_H
#define SQUID_ACLCERTIFICATE_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLCertificateStrategy : public ACLStrategy<X509 *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLCertificateStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLCertificateStrategy(ACLCertificateStrategy const &);

private:
    static ACLCertificateStrategy Instance_;
    ACLCertificateStrategy() {}

    ACLCertificateStrategy&operator=(ACLCertificateStrategy const &);
};

/// \ingroup ACLAPI
class ACLCertificate
{

private:
    static ACL::Prototype UserRegistryProtoype;
    static ACLStrategised<X509*> UserRegistryEntry_;
    static ACL::Prototype CARegistryProtoype;
    static ACLStrategised<X509 *> CARegistryEntry_;
};

#endif /* SQUID_ACLCERTIFICATE_H */

