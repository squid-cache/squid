/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * ----------------------------------------------------------------------------
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
#include "util.h"

#if HAVE_LDAP && HAVE_KRB5

#include "support.h"

#if HAVE_KRB5
extern struct kstruct kparam;
#endif

#define KT_PATH_MAX 256

void
krb5_cleanup()
{
    if (kparam.context)
        for (int i=0; i<MAX_DOMAINS; i++) {
            if (kparam.cc[i])
                krb5_cc_destroy(kparam.context, kparam.cc[i]);
            safe_free(kparam.mem_ccache[i]);
        }
    krb5_free_context(kparam.context);
}

static void
k5_error2(const char* msg, char* msg2, krb5_error_code code)
{
    const char *errmsg;
    errmsg = krb5_get_error_message(kparam.context, code);
    error((char *) "%s| %s: ERROR: %s%s : %s\n", LogTime(), PROGRAM, msg, msg2, errmsg);
#if HAVE_KRB5_FREE_ERROR_MESSAGE
    krb5_free_error_message(kparam.context, errmsg);
#elif HAVE_KRB5_FREE_ERROR_STRING
    krb5_free_error_string(kparam.context, (char *)errmsg);
#else
    xfree(errmsg);
#endif
}

static void
k5_error(const char* msg, krb5_error_code code)
{
    k5_error2(msg, (char *)"", code);
}

/*
 * create Kerberos memory cache
 */
int
krb5_create_cache(char *domain)
{

    krb5_keytab keytab = NULL;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    krb5_cc_cursor ccursor;
    krb5_creds *creds = NULL;
    krb5_principal *principal_list = NULL;
    krb5_principal principal = NULL;
    char *service;
    char *keytab_name = NULL, *principal_name = NULL, *mem_cache = NULL;
    char buf[KT_PATH_MAX], *p;
    size_t j,nprinc = 0;
    int retval = 0;
    krb5_error_code code = 0;
    int ccindex=-1;

    if (!domain || !strcmp(domain, ""))
        return (1);

    /*
     * prepare memory credential cache
     */
#if  !HAVE_KRB5_MEMORY_CACHE || HAVE_SUN_LDAP_SDK
    mem_cache = (char *) xmalloc(strlen("FILE:/tmp/squid_ldap_") + strlen(domain) + 1 + 16);
    snprintf(mem_cache, strlen("FILE:/tmp/squid_ldap_") + strlen(domain) + 1 + 16, "FILE:/tmp/squid_ldap_%s_%d", domain, (int) getpid());
#else
    mem_cache = (char *) xmalloc(strlen("MEMORY:squid_ldap_") + strlen(domain) + 1 + 16);
    snprintf(mem_cache, strlen("MEMORY:squid_ldap_") + strlen(domain) + 1 + 16, "MEMORY:squid_ldap_%s_%d", domain, (int) getpid());
#endif

    setenv("KRB5CCNAME", mem_cache, 1);
    debug((char *) "%s| %s: DEBUG: Set credential cache to %s\n", LogTime(), PROGRAM, mem_cache);
    for (int i=0; i<MAX_DOMAINS; i++) {
        if (kparam.mem_ccache[i] && !strcmp(mem_cache,kparam.mem_ccache[i])) {
            ccindex=i;
            break;
        }
    }
    if ( ccindex == -1 ) {
        kparam.mem_ccache[kparam.ncache]=xstrdup(mem_cache);
        ccindex=kparam.ncache;
        kparam.ncache++;
        if ( kparam.ncache == MAX_DOMAINS ) {
            error((char *) "%s| %s: ERROR: Too many domains to support: # domains %d\n", LogTime(), PROGRAM, kparam.ncache);
            retval = 1;
            goto cleanup;
        }
        code = krb5_cc_resolve(kparam.context, mem_cache, &kparam.cc[ccindex]);
        if (code) {
            k5_error("Error while resolving memory ccache",code);
            retval = 1;
            goto cleanup;
        }
    }
    /*
     * getting default principal from cache
     */

    code = krb5_cc_get_principal(kparam.context, kparam.cc[ccindex], &principal);
    if (code) {
        if (principal)
            krb5_free_principal(kparam.context, principal);
        principal = NULL;
        k5_error("No default principal found in ccache",code);
    } else {
        /*
         * Look for krbtgt and check if it is expired (or soon to be expired)
         */
        code = krb5_cc_start_seq_get(kparam.context, kparam.cc[ccindex], &ccursor);
        if (code) {
            k5_error("Error while starting ccache scan",code);
            code = krb5_cc_close (kparam.context, kparam.cc[ccindex]);
            if (code) {
                k5_error("Error while closing ccache",code);
            }
            if (kparam.cc[ccindex]) {
                code = krb5_cc_destroy(kparam.context, kparam.cc[ccindex]);
                if (code) {
                    k5_error("Error while destroying ccache",code);
                }
            }
        } else {
            krb5_error_code code2 = 0;
            creds = static_cast<krb5_creds *>(xcalloc(1,sizeof(*creds)));
            while ((krb5_cc_next_cred(kparam.context, kparam.cc[ccindex], &ccursor, creds)) == 0) {
                code2 = krb5_unparse_name(kparam.context, creds->server, &principal_name);
                if (code2) {
                    k5_error("Error while unparsing principal",code2);
                    code = krb5_cc_destroy(kparam.context, kparam.cc[ccindex]);
                    if (code) {
                        k5_error("Error while destroying ccache",code);
                    }
                    assert(creds != NULL);
                    krb5_free_creds(kparam.context, creds);
                    creds = NULL;
                    safe_free(principal_name);
                    debug((char *) "%s| %s: DEBUG: Reset credential cache to %s\n", LogTime(), PROGRAM, mem_cache);
                    code = krb5_cc_resolve(kparam.context, mem_cache, &kparam.cc[ccindex]);
                    if (code) {
                        k5_error("Error  while resolving memory ccache",code);
                        retval = 1;
                        goto cleanup;
                    }
                    code =1;
                    break;
                }
                if (!strncmp(KRB5_TGS_NAME,principal_name,KRB5_TGS_NAME_SIZE)) {
                    time_t now;
                    static krb5_deltat skew=MAX_SKEW;

                    debug((char *) "%s| %s: DEBUG: Found %s in cache : %s\n", LogTime(), PROGRAM,KRB5_TGS_NAME,principal_name);
                    /*
                     * Check time
                     */
                    time(&now);
                    debug((char *) "%s| %s: DEBUG: credential time diff %d\n", LogTime(), PROGRAM, (int)(creds->times.endtime - now));
                    if (creds->times.endtime - now < 2*skew) {
                        debug((char *) "%s| %s: DEBUG: credential will soon expire %d\n", LogTime(), PROGRAM, (int)(creds->times.endtime - now));
                        if (principal)
                            krb5_free_principal(kparam.context, principal);
                        principal = NULL;
                        code = krb5_cc_destroy(kparam.context, kparam.cc[ccindex]);
                        if (code) {
                            k5_error("Error  while destroying ccache",code);
                        }
                        assert(creds != NULL);
                        krb5_free_creds(kparam.context, creds);
                        creds = NULL;
                        safe_free(principal_name);
                        debug((char *) "%s| %s: DEBUG: Reset credential cache to %s\n", LogTime(), PROGRAM, mem_cache);
                        code = krb5_cc_resolve(kparam.context, mem_cache, &kparam.cc[ccindex]);
                        if (code) {
                            k5_error("Error  while resolving ccache",code);
                            retval = 1;
                            goto cleanup;
                        }
                        code = 1;
                    } else {
                        safe_free(principal_name);
                    }
                    break;
                }
                assert(creds != NULL);
                krb5_free_creds(kparam.context, creds);
                creds = static_cast<krb5_creds *>(xcalloc(1, sizeof(*creds)));
                safe_free(principal_name);
            }
            if (creds)
                krb5_free_creds(kparam.context, creds);
            creds = NULL;
            code2 = krb5_cc_end_seq_get(kparam.context, kparam.cc[ccindex], &ccursor);
            if (code2) {
                k5_error("Error  while ending ccache scan",code2);
                retval = 1;
                goto cleanup;
            }
        }
    }
    if (code) {
        /*
         * getting default keytab name
         */

        debug((char *) "%s| %s: DEBUG: Get default keytab file name\n", LogTime(), PROGRAM);
        krb5_kt_default_name(kparam.context, buf, KT_PATH_MAX);
        p = strchr(buf, ':');   /* Find the end if "FILE:" */
        if (p)
            ++p;            /* step past : */
        keytab_name = xstrdup(p ? p : buf);
        debug((char *) "%s| %s: DEBUG: Got default keytab file name %s\n", LogTime(), PROGRAM, keytab_name);

        code = krb5_kt_resolve(kparam.context, keytab_name, &keytab);
        if (code) {
            k5_error2("Error while resolving keytab ",keytab_name,code);
            retval = 1;
            goto cleanup;
        }
        code = krb5_kt_start_seq_get(kparam.context, keytab, &cursor);
        if (code) {
            k5_error("Error while starting keytab scan",code);
            retval = 1;
            goto cleanup;
        }
        debug((char *) "%s| %s: DEBUG: Get principal name from keytab %s\n", LogTime(), PROGRAM, keytab_name);

        nprinc = 0;
        while ((code = krb5_kt_next_entry(kparam.context, keytab, &entry, &cursor)) == 0) {
            int found = 0;

            principal_list = (krb5_principal *) xrealloc(principal_list, sizeof(krb5_principal) * (nprinc + 1));
            krb5_copy_principal(kparam.context, entry.principal, &principal_list[nprinc++]);
#if USE_HEIMDAL_KRB5
            debug((char *) "%s| %s: DEBUG: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, entry.principal->realm);
#else
            debug((char *) "%s| %s: DEBUG: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, krb5_princ_realm(kparam.context, entry.principal)->data);
#endif
#if USE_HEIMDAL_KRB5
            if (!strcasecmp(domain, entry.principal->realm))
#else
            if (!strcasecmp(domain, krb5_princ_realm(kparam.context, entry.principal)->data))
#endif
            {
                code = krb5_unparse_name(kparam.context, entry.principal, &principal_name);
                if (code) {
                    k5_error("Error while unparsing principal name",code);
                } else {
                    debug((char *) "%s| %s: DEBUG: Found principal name: %s\n", LogTime(), PROGRAM, principal_name);
                    found = 1;
                }
            }
#if USE_HEIMDAL_KRB5 || ( HAVE_KRB5_KT_FREE_ENTRY && HAVE_DECL_KRB5_KT_FREE_ENTRY )
            code = krb5_kt_free_entry(kparam.context, &entry);
#else
            code = krb5_free_keytab_entry_contents(kparam.context, &entry);
#endif
            if (code) {
                k5_error("Error while freeing keytab entry",code);
                retval = 1;
                break;
            }
            if (found) {
                debug((char *) "%s| %s: DEBUG: Got principal name %s\n", LogTime(), PROGRAM, principal_name);
                /*
                 * build principal
                 */
                code = krb5_parse_name(kparam.context, principal_name, &principal);
                if (code) {
                    k5_error2("Error while parsing name ", principal_name,code);
                    safe_free(principal_name);
                    if (principal)
                        krb5_free_principal(kparam.context, principal);
                    found = 0;
                    continue;
                }
                creds = (krb5_creds *) xcalloc(1,sizeof(*creds));

                /*
                 * get credentials
                 */
#if HAVE_GET_INIT_CREDS_KEYTAB
                code = krb5_get_init_creds_keytab(kparam.context, creds, principal, keytab, 0, NULL, NULL);
#else
                service = (char *) xmalloc(strlen("krbtgt") + 2 * strlen(domain) + 3);
                snprintf(service, strlen("krbtgt") + 2 * strlen(domain) + 3, "krbtgt/%s@%s", domain, domain);
                creds->client = principal;
                code = krb5_parse_name(kparam.context, service, &creds->server);
                xfree(service);
                code = krb5_get_in_tkt_with_keytab(kparam.context, 0, NULL, NULL, NULL, keytab, NULL, creds, 0);
#endif

                if (code) {
                    k5_error("Error while initialising credentials from keytab" ,code);
                    safe_free(principal_name);
                    if (principal)
                        krb5_free_principal(kparam.context, principal);
                    if (creds)
                        krb5_free_creds(kparam.context, creds);
                    creds = NULL;
                    found = 0;
                    continue;
                }
                code = krb5_cc_initialize(kparam.context, kparam.cc[ccindex], principal);
                if (code) {
                    k5_error("Error while initialising  memory caches" ,code);
                    safe_free(principal_name);
                    if (principal)
                        krb5_free_principal(kparam.context, principal);
                    if (creds)
                        krb5_free_creds(kparam.context, creds);
                    creds = NULL;
                    found = 0;
                    continue;
                }
                code = krb5_cc_store_cred(kparam.context, kparam.cc[ccindex], creds);
                if (code) {
                    k5_error("Error while storing credentials" ,code);
                    if (principal)
                        krb5_free_principal(kparam.context, principal);
                    safe_free(principal_name);
                    if (creds)
                        krb5_free_creds(kparam.context, creds);
                    creds = NULL;
                    found = 0;
                    continue;
                }
                debug((char *) "%s| %s: DEBUG: Stored credentials\n", LogTime(), PROGRAM);
                break;
            }
        }

        if (code && code != KRB5_KT_END) {
            k5_error("Error while scanning keytab" ,code);
            retval = 1;
            goto cleanup;
        }
        code = krb5_kt_end_seq_get(kparam.context, keytab, &cursor);
        if (code) {
            k5_error("Error while ending keytab scan" ,code);
            retval = 1;
            goto cleanup;
        }

        /*
         * if no principal name found in keytab for domain use the prinipal name which can get a TGT
         */
        if (!principal_name) {
            size_t i;
            debug((char *) "%s| %s: DEBUG: Did not find a principal in keytab for domain %s.\n", LogTime(), PROGRAM, domain);
            debug((char *) "%s| %s: DEBUG: Try to get principal of trusted domain.\n", LogTime(), PROGRAM);

            for (i = 0; i < nprinc; ++i) {
                krb5_creds *tgt_creds = NULL;
                creds = (krb5_creds *) xmalloc(sizeof(*creds));
                memset(creds, 0, sizeof(*creds));
                /*
                 * get credentials
                 */
                code = krb5_unparse_name(kparam.context, principal_list[i], &principal_name);
                if (code) {
                    k5_error("Error while unparsing principal name" ,code);
                    goto loop_end;
                }
                debug((char *) "%s| %s: DEBUG: Keytab entry has principal: %s\n", LogTime(), PROGRAM, principal_name);

#if HAVE_GET_INIT_CREDS_KEYTAB
                code = krb5_get_init_creds_keytab(kparam.context, creds, principal_list[i], keytab, 0, NULL, NULL);
#else
                service = (char *) xmalloc(strlen("krbtgt") + 2 * strlen(domain) + 3);
                snprintf(service, strlen("krbtgt") + 2 * strlen(domain) + 3, "krbtgt/%s@%s", domain, domain);
                creds->client = principal_list[i];
                code = krb5_parse_name(kparam.context, service, &creds->server);
                xfree(service);
                code = krb5_get_in_tkt_with_keytab(kparam.context, 0, NULL, NULL, NULL, keytab, NULL, creds, 0);
#endif
                if (code) {
                    k5_error("Error while initialising credentials from keytab" ,code);
                    goto loop_end;
                }
                code = krb5_cc_initialize(kparam.context, kparam.cc[ccindex], principal_list[i]);
                if (code) {
                    k5_error("Error while initialising memory caches" ,code);
                    goto loop_end;
                }
                code = krb5_cc_store_cred(kparam.context, kparam.cc[ccindex], creds);
                if (code) {
                    k5_error("Error while storing credentials" ,code);
                    goto loop_end;
                }
                if (creds->server)
                    krb5_free_principal(kparam.context, creds->server);
#if USE_HEIMDAL_KRB5
                service = (char *) xmalloc(strlen("krbtgt") + strlen(domain) + strlen(principal_list[i]->realm) + 3);
                snprintf(service, strlen("krbtgt") + strlen(domain) + strlen(principal_list[i]->realm) + 3, "krbtgt/%s@%s", domain, principal_list[i]->realm);
#else
                service = (char *) xmalloc(strlen("krbtgt") + strlen(domain) + strlen(krb5_princ_realm(kparam.context, principal_list[i])->data) + 3);
                snprintf(service, strlen("krbtgt") + strlen(domain) + strlen(krb5_princ_realm(kparam.context, principal_list[i])->data) + 3, "krbtgt/%s@%s", domain, krb5_princ_realm(kparam.context, principal_list[i])->data);
#endif
                code = krb5_parse_name(kparam.context, service, &creds->server);
                xfree(service);
                if (code) {
                    k5_error("Error while initialising TGT credentials" ,code);
                    goto loop_end;
                }
                code = krb5_get_credentials(kparam.context, 0, kparam.cc[ccindex], creds, &tgt_creds);
                if (code) {
                    k5_error("Error while getting tgt" ,code);
                    goto loop_end;
                } else {
                    debug((char *) "%s| %s: DEBUG: Found trusted principal name: %s\n", LogTime(), PROGRAM, principal_name);
                    if (tgt_creds)
                        krb5_free_creds(kparam.context, tgt_creds);
                    tgt_creds = NULL;
                    break;
                }

loop_end:
                safe_free(principal_name);
                if (tgt_creds)
                    krb5_free_creds(kparam.context, tgt_creds);
                tgt_creds = NULL;
                if (creds)
                    krb5_free_creds(kparam.context, creds);
                creds = NULL;

            }

            if (creds)
                krb5_free_creds(kparam.context, creds);
            creds = NULL;
        }
    } else {
        debug((char *) "%s| %s: DEBUG: Got principal from ccache\n", LogTime(), PROGRAM);
        /*
         * get credentials
         */
        code = krb5_unparse_name(kparam.context, principal, &principal_name);
        if (code) {
            k5_error("Error while unparsing principal name" ,code);
            retval = 1;
            goto cleanup;
        }
        debug((char *) "%s| %s: DEBUG: ccache has principal: %s\n", LogTime(), PROGRAM, principal_name);
    }

    if (!principal_name) {
        debug((char *) "%s| %s: DEBUG: Got no principal name\n", LogTime(), PROGRAM);
        retval = 1;
    }
cleanup:
    if (keytab)
        krb5_kt_close(kparam.context, keytab);
    xfree(keytab_name);
    xfree(principal_name);
    xfree(mem_cache);
    if (principal)
        krb5_free_principal(kparam.context, principal);
    for (j = 0; j < nprinc; ++j) {
        if (principal_list[j])
            krb5_free_principal(kparam.context, principal_list[j]);
    }
    xfree(principal_list);
    if (creds)
        krb5_free_creds(kparam.context, creds);
    return (retval);
}
#endif

