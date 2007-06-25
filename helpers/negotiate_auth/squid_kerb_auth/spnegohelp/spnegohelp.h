/* -----------------------------------------------------------------------------
 * spnegohelp.c declares RFC 2478 SPNEGO GSS-API mechanism APIs.
 *
 * Author: Frank Balluffi
 *
 * Copyright (C) 2002-2003. All rights reserved.
 * -----------------------------------------------------------------------------
 */

#ifndef SPNEGOHELP_H
#define SPNEGOHELP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* -----------------------------------------------------------------------------
 * makeNegTokenTarg makes an RFC 2478 SPNEGO NegTokenTarg (token) from an
 * RFC 1964 Kerberos GSS-API token.
 *
 * If makeNegTokenTarg is successful, call free (*negTokenTarg) to free the
 * memory allocated by parseNegTokenInit.
 *
 * Returns 0 if successful, 1 otherwise.
 * -----------------------------------------------------------------------------
 */

int makeNegTokenTarg (const unsigned char *  kerberosToken,
                      size_t                 kerberosTokenLength,
                      const unsigned char ** negTokenTarg,
                      size_t *               negTokenTargLength);

/* -----------------------------------------------------------------------------
 * parseNegTokenInit parses an RFC 2478 SPNEGO NegTokenInit (token) to extract
 * an RFC 1964 Kerberos GSS-API token.
 *
 * If the NegTokenInit does cotain a Kerberos GSS-API token, parseNegTokenInit
 * returns an error.
 *
 * If parseNegTokenInit is successful, call free (*kerberosToken) to
 * free the memory allocated by parseNegTokenInit.
 *
 * Returns 0 if successful, 1 otherwise.
 * -----------------------------------------------------------------------------
 */

int parseNegTokenInit (const unsigned char *  negTokenInit,
                       size_t                 negTokenInitLength,
                       const unsigned char ** kerberosToken,
                       size_t *               kerberosTokenLength);

#ifdef __cplusplus
}
#endif

#endif /* SPNEGOHELP_H */
