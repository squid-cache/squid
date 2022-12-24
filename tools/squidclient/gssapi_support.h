/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_TOOLS_SQUIDCLIENT_GSSAPI_H
#define _SQUID_TOOLS_SQUIDCLIENT_GSSAPI_H

#if HAVE_GSSAPI
#if USE_APPLE_KRB5
#define GSSKRB_APPLE_DEPRECATED(x)
#endif

#if USE_HEIMDAL_KRB5
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif /* HAVE_GSSAPI_GSSAPI_H/HAVE_GSSAPI_H */
#elif USE_GNUGSS
#if HAVE_GSS_H
#include <gss.h>
#endif
#else
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif /* HAVE_GSSAPI_GSSAPI_H/HAVE_GSSAPI_H */
#if HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif
#if HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif
#if HAVE_GSSAPI_GSSAPI_EXT_H
#include <gssapi/gssapi_ext.h>
#endif
#endif

#ifndef gss_nt_service_name
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#endif

bool check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char *function);
char *GSSAPI_token(const char *server);

#endif /* HAVE_GSSAPI */
#endif /* _SQUID_TOOLS_SQUIDCLIENT_GSSAPI_H */

