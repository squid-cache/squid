#ifndef SQUID__HELPERS_NEGOTIATE_AUTH_SQUID_KERB_AUTH_SQUID_COMPAT_H
#define SQUID__HELPERS_NEGOTIATE_AUTH_SQUID_KERB_AUTH_SQUID_COMPAT_H

/*
 * We use a HAVE_SQUID define to override ther Squid-specific package
 * definitions for their includes.
 * AYJ: This whole bit needs re-working when compat.h exists.
 * We will only need the compat.h and its library from squid.
 */

#if HAVE_SQUID

#include "config.h"

/* We want the Squid type and library definitions without the package ones */
#undef VERSION
#undef PACKAGE
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#endif /* HAVE_SQUID */

#endif /* SQUID__HELPERS_NEGOTIATE_AUTH_SQUID_KERB_AUTH_SQUID_COMPAT_H */
