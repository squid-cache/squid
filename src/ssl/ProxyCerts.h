/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSLPROXYCERTS_H_
#define SQUID_SSLPROXYCERTS_H_

#if USE_OPENSSL
#include "acl/forward.h"

class sslproxy_cert_sign
{
public:
    int alg;
    ACLList *aclList;
    sslproxy_cert_sign *next;
};

class sslproxy_cert_adapt
{
public:
    int alg;
    char *param;
    ACLList *aclList;
    sslproxy_cert_adapt *next;
};
#endif

#endif /* SQUID_SSLPROXYCERTS_H_ */

