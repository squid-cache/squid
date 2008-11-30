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
/*
 * Hosted at http://sourceforge.net/projects/squidkerbauth
 */

#include "ska_config.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif


#if !defined(HAVE_DECL_XMALLOC) || !HAVE_DECL_XMALLOC
#define xmalloc malloc
#endif
#if !defined(HAVE_DECL_XSTRDUP) || !HAVE_DECL_XSTRDUP
#define xstrdup strdup
#endif

#include "base64.h"

static const char *LogTime(void);

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function);

const char *squid_kerb_proxy_auth(char *proxy);

#define PROGRAM "squid_kerb_auth_test"

static const char *LogTime()
{
    struct tm *tm;
    struct timeval now;
    static time_t last_t = 0;
    static char buf[128];

    gettimeofday(&now, NULL);
    if (now.tv_sec != last_t) {
        // FreeBSD defines tv_sec as long in non-ARM systems with a TODO note
        time_t tmp = now.tv_sec;
        tm = localtime(&tmp);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

#ifdef HAVE_SPNEGO
#ifndef gss_mech_spnego
static gss_OID_desc _gss_mech_spnego  = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
gss_OID gss_mech_spnego = &_gss_mech_spnego;
#endif
#endif

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function)
{
    if (GSS_ERROR(major_status)) {
        OM_uint32 maj_stat,min_stat;
        OM_uint32 msg_ctx = 0;
        gss_buffer_desc status_string;
        char buf[1024];
        size_t len;

        len = 0;
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert major status code (GSS-API error) to text */
            maj_stat = gss_display_status(&min_stat, major_status,
                                          GSS_C_GSS_CODE,
                                          GSS_C_NULL_OID,
                                          &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                if (sizeof(buf) > len + status_string.length + 1) {
                    sprintf(buf+len, "%s", (char*) status_string.value);
                    len += status_string.length;
                }
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        if (sizeof(buf) > len + 2) {
            sprintf(buf+len, "%s", ". ");
            len += 2;
        }
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert minor status code (underlying routine error) to text */
            maj_stat = gss_display_status(&min_stat, minor_status,
                                          GSS_C_MECH_CODE,
                                          GSS_C_NULL_OID,
                                          &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                if (sizeof(buf) > len + status_string.length ) {
                    sprintf(buf+len, "%s", (char*) status_string.value);
                    len += status_string.length;
                }
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        fprintf(stderr, "%s| %s: %s failed: %s\n", LogTime(), PROGRAM, function, buf);
        return(1);
    }
    return(0);
}

const char *squid_kerb_proxy_auth(char *proxy)
{
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t          gss_context = GSS_C_NO_CONTEXT;
    gss_name_t            server_name = GSS_C_NO_NAME;
    gss_buffer_desc       service = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc       input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc       output_token = GSS_C_EMPTY_BUFFER;
    char   *token = NULL;

    setbuf(stdout,NULL);
    setbuf(stdin,NULL);

    if (!proxy ) {
        fprintf(stderr, "%s| %s: Error: No proxy server name\n", LogTime(), PROGRAM);
        return NULL;
    }

    service.value = xmalloc(strlen("HTTP")+strlen(proxy)+2);
    snprintf(service.value,strlen("HTTP")+strlen(proxy)+2,"%s@%s","HTTP",proxy);
    service.length = strlen((char *)service.value);

    major_status = gss_import_name(&minor_status, &service,
                                   gss_nt_service_name, &server_name);

    if (check_gss_err(major_status,minor_status,"gss_import_name()") )
        goto cleanup;

    major_status = gss_init_sec_context(&minor_status,
                                        GSS_C_NO_CREDENTIAL,
                                        &gss_context,
                                        server_name,
#ifdef HAVE_SPNEGO
                                        gss_mech_spnego,
#else
                                        0,
#endif
                                        0,
                                        0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token,
                                        NULL,
                                        &output_token,
                                        NULL,
                                        NULL);

    if (check_gss_err(major_status,minor_status,"gss_init_sec_context()") )
        goto cleanup;

    if (output_token.length) {
        token=xmalloc(ska_base64_encode_len(output_token.length));
        ska_base64_encode(token,(const char*)output_token.value,ska_base64_encode_len(output_token.length),output_token.length);
    }


cleanup:
    gss_delete_sec_context(&minor_status, &gss_context, NULL);
    gss_release_buffer(&minor_status, &service);
    gss_release_buffer(&minor_status, &input_token);
    gss_release_buffer(&minor_status, &output_token);
    gss_release_name(&minor_status, &server_name);

    return token;
}

int main(int argc, char *argv[])
{

    const char *Token;

    if (argc < 1) {
        fprintf(stderr, "%s| %s: Error: No proxy server name given\n", LogTime(), PROGRAM);
        exit(99);
    }
    Token = (const char *)squid_kerb_proxy_auth(argv[1]);
    fprintf(stdout,"Token: %s\n",Token?Token:"NULL");

    exit(0);
}

