/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_FORWARD_H
#define SQUID_SRC_SECURITY_FORWARD_H

#include "security/Context.h"

/* flags a SSL connection can be configured with */
#define SSL_FLAG_NO_DEFAULT_CA      (1<<0)
#define SSL_FLAG_DELAYED_AUTH       (1<<1)
#define SSL_FLAG_DONT_VERIFY_PEER   (1<<2)
#define SSL_FLAG_DONT_VERIFY_DOMAIN (1<<3)
#define SSL_FLAG_NO_SESSION_REUSE   (1<<4)
#define SSL_FLAG_VERIFY_CRL         (1<<5)
#define SSL_FLAG_VERIFY_CRL_ALL     (1<<6)

/// Network/connection security abstraction layer
namespace Security
{

class EncryptorAnswer;
class PeerOptions;

} // namespace Security

#endif /* SQUID_SRC_SECURITY_FORWARD_H */

