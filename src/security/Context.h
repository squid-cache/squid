/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CONTEXT_H
#define SQUID_SRC_SECURITY_CONTEXT_H

#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

namespace Security {

#if USE_OPENSSL
// XXX: make this a SSL_CTX_Pointer
typedef SSL_CTX* ContextPointer;

#else
// use void* so we can check against NULL
typedef void* ContextPointer;
#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */

