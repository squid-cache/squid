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

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/Scheme.h"
#endif

#include "base/Assure.h"
#include "debug/Messages.h"
#include "debug/Stream.h"

/**
 * Initialize the authentication modules (if any)
 * This is required once, before any configuration actions are taken.
 */
void
Auth::Init()
{
    debugs(29, Important(69), "Startup: Initializing Authentication Schemes ...");
#if HAVE_AUTH_MODULE_BASIC
    Assure(Basic::Scheme::GetInstance());
    debugs(29, Important(70), "Startup: Initialized Authentication Scheme 'basic'");
#endif
#if HAVE_AUTH_MODULE_DIGEST
    Assure(Digest::Scheme::GetInstance());
    debugs(29, Important(71), "Startup: Initialized Authentication Scheme 'digest'");
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
    Assure(Negotiate::Scheme::GetInstance());
    debugs(29, Important(72), "Startup: Initialized Authentication Scheme 'negotiate'");
#endif
}

#endif /* USE_AUTH */

