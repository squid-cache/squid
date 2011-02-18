#include "config.h"

#if USE_AUTH

#include "Debug.h"
#include "protos.h"

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/basicScheme.h"
#endif
#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/digestScheme.h"
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/negotiateScheme.h"
#endif
#if HAVE_AUTH_MODULE_NTLM
#include "auth/ntlm/ntlmScheme.h"
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
    static const char *basic_type = basicScheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << basic_type << "'");
#endif
#if HAVE_AUTH_MODULE_DIGEST
    static const char *digest_type = digestScheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << digest_type << "'");
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
    static const char *negotiate_type = negotiateScheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << negotiate_type << "'");
#endif
#if HAVE_AUTH_MODULE_NTLM
    static const char *ntlm_type = ntlmScheme::GetInstance()->type();
    debugs(29,1,"Initialized Authentication Scheme '" << ntlm_type << "'");
#endif
    debugs(29,1,"Initializing Authentication Schemes Complete.");
}

#endif /* USE_AUTH */
