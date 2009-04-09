#include "squid.h"


#ifdef HAVE_AUTH_MODULE_BASIC
#include "auth/basic/basicScheme.h"
#endif

#ifdef HAVE_AUTH_MODULE_NTLM
#include "auth/ntlm/ntlmScheme.h"
#endif

#ifdef HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/digestScheme.h"
#endif

#ifdef HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/negotiateScheme.h"
#endif

#ifdef HAVE_AUTH_MODULE_BASIC
static const char *basic_type = basicScheme::GetInstance().type();
#endif

#ifdef HAVE_AUTH_MODULE_NTLM
static const char *ntlm_type = ntlmScheme::GetInstance().type();
#endif

#ifdef HAVE_AUTH_MODULE_DIGEST
static const char *digest_type = digestScheme::GetInstance().type();
#endif

#ifdef HAVE_AUTH_MODULE_NEGOTIATE
static const char *negotiate_type = negotiateScheme::GetInstance().type();
#endif

