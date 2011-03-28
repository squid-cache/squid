#include "config.h"

#if USE_AUTH

#include "Debug.h"
#include "protos.h"

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/Scheme.h"
#endif
#if HAVE_AUTH_MODULE_NTLM
#include "auth/ntlm/Scheme.h"
#endif

/**
 * Initialize the authentication modules (if any)
 * This is required once, before any configuration actions are taken.
 */
void
InitAuthSchemes()
{
    debugs(29,1,"Initializing Authentication Schemes ...");
#if HAVE_AUTH_MODULE_BASIC
    static const char *basic_type = Auth::Basic::Scheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << basic_type << "'");
#endif
#if HAVE_AUTH_MODULE_DIGEST
    static const char *digest_type = Auth::Digest::Scheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << digest_type << "'");
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
    static const char *negotiate_type = Auth::Negotiate::Scheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << negotiate_type << "'");
#endif
#if HAVE_AUTH_MODULE_NTLM
    static const char *ntlm_type = Auth::Ntlm::Scheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << ntlm_type << "'");
#endif
    debugs(29,1,"Initializing Authentication Schemes Complete.");
}

#endif /* USE_AUTH */
