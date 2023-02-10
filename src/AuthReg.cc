/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_AUTH
#include "AuthReg.h"
#include "debug/Messages.h"

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/Scheme.h"
#endif

#include "debug/Stream.h"

/**
 * Initialize the authentication modules (if any)
 * This is required once, before any configuration actions are taken.
 */
void
Auth::Init()
{
    debugs(29, Important(68), "Startup: Initializing Authentication Schemes ...");
#if HAVE_AUTH_MODULE_BASIC
    static const char *basic_type = Auth::Basic::Scheme::GetInstance()->type();
    debugs(29, Important(69), "Startup: Initialized Authentication Scheme '" << basic_type << "'");
#endif
#if HAVE_AUTH_MODULE_DIGEST
    static const char *digest_type = Auth::Digest::Scheme::GetInstance()->type();
    debugs(29, Important(70), "Startup: Initialized Authentication Scheme '" << digest_type << "'");
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
    static const char *negotiate_type = Auth::Negotiate::Scheme::GetInstance()->type();
    debugs(29, Important(71), "Startup: Initialized Authentication Scheme '" << negotiate_type << "'");
#endif
}

#endif /* USE_AUTH */

