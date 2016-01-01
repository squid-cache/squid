/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * -----------------------------------------------------------------------------
 */

#include "squid.h"

#if HAVE_GSSAPI
#if USE_APPLE_KRB5
#define GSSKRB_APPLE_DEPRECATED(x)
#endif

#include <cerrno>
#include <cstring>
#include <ctime>
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "base64.h"
#include "util.h"

#if USE_HEIMDAL_KRB5
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif
#elif USE_GNUGSS
#if HAVE_GSS_H
#include <gss.h>
#endif
#else
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif
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

static const char *LogTime(void);

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
                  const char *function);

const char *squid_kerb_proxy_auth(char *proxy);

#define PROGRAM "negotiate_kerberos_auth_test"

static const char *
LogTime()
{
    struct tm *tm;
    struct timeval now;
    static time_t last_t = 0;
    static char buf[128];

    gettimeofday(&now, NULL);
    if (now.tv_sec != last_t) {
        tm = localtime((const time_t *) &now.tv_sec);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

#ifndef gss_mech_spnego
static gss_OID_desc _gss_mech_spnego = {6, (void *) "\x2b\x06\x01\x05\x05\x02"};
gss_OID gss_mech_spnego = &_gss_mech_spnego;
#endif

int
check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
              const char *function)
{
    if (GSS_ERROR(major_status)) {
        OM_uint32 maj_stat, min_stat;
        OM_uint32 msg_ctx = 0;
        gss_buffer_desc status_string;
        char buf[1024];
        size_t len;

        len = 0;
        msg_ctx = 0;
        do {
            /* convert major status code (GSS-API error) to text */
            maj_stat = gss_display_status(&min_stat, major_status,
                                          GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE && status_string.length > 0) {
                if (sizeof(buf) > len + status_string.length + 1) {
                    snprintf(buf + len, (sizeof(buf) - len), "%s", (char *) status_string.value);
                    len += status_string.length;
                }
            } else
                msg_ctx = 0;
            gss_release_buffer(&min_stat, &status_string);
        } while (msg_ctx);
        if (sizeof(buf) > len + 2) {
            snprintf(buf + len, (sizeof(buf) - len), "%s", ". ");
            len += 2;
        }
        msg_ctx = 0;
        do {
            /* convert minor status code (underlying routine error) to text */
            maj_stat = gss_display_status(&min_stat, minor_status,
                                          GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE && status_string.length > 0) {
                if (sizeof(buf) > len + status_string.length) {
                    snprintf(buf + len, (sizeof(buf) - len), "%s", (char *) status_string.value);
                    len += status_string.length;
                }
            } else
                msg_ctx = 0;
            gss_release_buffer(&min_stat, &status_string);
        } while (msg_ctx);
        fprintf(stderr, "%s| %s: %s failed: %s\n", LogTime(), PROGRAM, function,
                buf);
        return (1);
    }
    return (0);
}

const char *
squid_kerb_proxy_auth(char *proxy)
{
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t server_name = GSS_C_NO_NAME;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    char *token = NULL;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    if (!proxy) {
        fprintf(stderr, "%s| %s: Error: No proxy server name\n", LogTime(),
                PROGRAM);
        return NULL;
    }
    service.value = xmalloc(strlen("HTTP") + strlen(proxy) + 2);
    snprintf((char *) service.value, strlen("HTTP") + strlen(proxy) + 2, "%s@%s", "HTTP", proxy);
    service.length = strlen((char *) service.value);

    major_status = gss_import_name(&minor_status, &service,
                                   gss_nt_service_name, &server_name);

    if (check_gss_err(major_status, minor_status, "gss_import_name()"))
        goto cleanup;

    major_status = gss_init_sec_context(&minor_status,
                                        GSS_C_NO_CREDENTIAL, &gss_context, server_name,
                                        gss_mech_spnego,
                                        0,
                                        0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token, NULL, &output_token, NULL, NULL);

    if (check_gss_err(major_status, minor_status, "gss_init_sec_context()"))
        goto cleanup;

    if (output_token.length) {
        token = (char *) xmalloc((size_t)base64_encode_len((int)output_token.length));
        base64_encode_str(token, base64_encode_len((int)output_token.length),
                          (const char *) output_token.value, (int)output_token.length);
    }
cleanup:
    gss_delete_sec_context(&minor_status, &gss_context, NULL);
    gss_release_buffer(&minor_status, &service);
    gss_release_buffer(&minor_status, &input_token);
    gss_release_buffer(&minor_status, &output_token);
    gss_release_name(&minor_status, &server_name);

    return token;
}

int
main(int argc, char *argv[])
{
    const char *Token;
    int count;

    if (argc < 2) {
        fprintf(stderr, "%s| %s: Error: No proxy server name given\n",
                LogTime(), PROGRAM);
        return 99;
    }
    if (argc == 3) {
        count = atoi(argv[2]);
        while (count > 0) {
            Token = (const char *) squid_kerb_proxy_auth(argv[1]);
            fprintf(stdout, "YR %s\n", Token ? Token : "NULL");
            --count;
        }
        fprintf(stdout, "QQ\n");
    } else {
        Token = (const char *) squid_kerb_proxy_auth(argv[1]);
        fprintf(stdout, "Token: %s\n", Token ? Token : "NULL");
    }

    return 0;
}

#else
#include <cstdlib>
int
main(int argc, char *argv[])
{
    return -1;
}

#endif /* HAVE_GSSAPI */

