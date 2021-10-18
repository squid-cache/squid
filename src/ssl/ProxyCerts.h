/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSLPROXYCERTS_H_
#define SQUID_SSLPROXYCERTS_H_

#if USE_OPENSSL
#include "acl/forward.h"
#include "acl/Gadgets.h"
#include "ssl/gadgets.h"

class sslproxy_cert_sign
{
public:
    sslproxy_cert_sign() = default;
    sslproxy_cert_sign(const sslproxy_cert_sign &) = delete; // prohibit all copy/move
    ~sslproxy_cert_sign() {
        if (aclList)
            aclDestroyAclList(&aclList);
        while (next) {
            auto *tmp = next;
            next = next->next;
            delete tmp;
        }
    }

public:
    Ssl::CertSignAlgorithm alg = Ssl::algSignEnd;
    ACLList *aclList = nullptr;
    sslproxy_cert_sign *next = nullptr;
};

class sslproxy_cert_adapt
{
public:
    sslproxy_cert_adapt() = default;
    sslproxy_cert_adapt(const sslproxy_cert_adapt &) = delete; // prohibit all copy/move
    ~sslproxy_cert_adapt() {
        xfree(param);
        if (aclList)
            aclDestroyAclList(&aclList);
        while (next) {
            auto *tmp = next;
            next = next->next;
            delete tmp;
        }
    }

public:
    Ssl::CertAdaptAlgorithm alg = Ssl::algSetEnd;
    char *param = nullptr;
    ACLList *aclList = nullptr;
    sslproxy_cert_adapt *next = nullptr;
};
#endif

#endif /* SQUID_SSLPROXYCERTS_H_ */

