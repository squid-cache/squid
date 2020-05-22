/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
 * Copyright (C) 2013 Markus Moeller. All rights reserved.
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
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */

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

#if USE_APPLE_KRB5
#define KERBEROS_APPLE_DEPRECATED(x)
#define GSSKRB_APPLE_DEPRECATED(x)
#endif

#if HAVE_KRB5_H
#if HAVE_BROKEN_SOLARIS_KRB5_H
#warn "Warning! You have a broken Solaris <krb5.h> system header"
#warn "http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6837512"
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif /* HAVE_BROKEN_SOLARIS_KRB5_H */
#if HAVE_BROKEN_HEIMDAL_KRB5_H
extern "C" {
#include <krb5.h>
}
#else
#include <krb5.h>
#endif
#endif /* HAVE_KRB5_H */

#if USE_HEIMDAL_KRB5
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif
#if HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
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

#define PROGRAM "negotiate_kerberos_auth"

#ifndef MAX_AUTHTOKEN_LEN
#define MAX_AUTHTOKEN_LEN   65535
#endif
#ifndef SQUID_KERB_AUTH_VERSION
#define SQUID_KERB_AUTH_VERSION "3.1.0sq"
#endif

char *gethost_name(void);

static const unsigned char ntlmProtocol[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

inline const char *
LogTime()
{
    struct timeval now;
    static time_t last_t = 0;
    static char buf[128];

    gettimeofday(&now, NULL);
    if (now.tv_sec != last_t) {
        struct tm *tm;
        tm = localtime((time_t *) & now.tv_sec);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
                  const char *function, int log, int sout);

char *gethost_name(void);

#if (HAVE_GSSKRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT || HAVE_GSS_MAP_NAME_TO_ANY) && HAVE_KRB5_PAC
#define HAVE_PAC_SUPPORT 1
#define MAX_PAC_GROUP_SIZE 200*60
typedef struct {
    uint16_t length;
    uint16_t maxlength;
    uint32_t pointer;
} RPC_UNICODE_STRING;

void align(int n);
void getustr(RPC_UNICODE_STRING *string);
char **getgids(char **Rids, uint32_t GroupIds, uint32_t GroupCount);
char *getdomaingids(char *ad_groups, uint32_t DomainLogonId, char **Rids, uint32_t  GroupCount);
char *getextrasids(char *ad_groups, uint32_t ExtraSids, uint32_t SidCount);
uint64_t get6byt_be(void);
uint32_t get4byt(void);
uint16_t get2byt(void);
uint8_t get1byt(void);
char *xstrcpy( char *src, const char*dst);
char *xstrcat( char *src, const char*dst);
int checkustr(RPC_UNICODE_STRING *string);
char *get_ad_groups(char *ad_groups, krb5_context context, krb5_pac pac);
#else
#define HAVE_PAC_SUPPORT 0
#endif
int check_k5_err(krb5_context context, const char *msg, krb5_error_code code);

