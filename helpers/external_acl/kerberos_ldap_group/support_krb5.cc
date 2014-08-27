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

#if defined(HAVE_LDAP) && defined(HAVE_KRB5)

#include "support.h"

struct kstruct {
    krb5_context context;
    char *mem_cache_env;
    krb5_ccache cc;
};

static struct kstruct kparam;

#define KT_PATH_MAX 256

void
krb5_cleanup()
{
    if (kparam.context) {
        if (kparam.cc)
            krb5_cc_destroy(kparam.context, kparam.cc);
        krb5_free_context(kparam.context);
    }
}
/*
 * create Kerberos memory cache
 */
int
krb5_create_cache(char *domain)
{

    krb5_keytab keytab = 0;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    krb5_creds *creds = NULL;
    krb5_principal *principal_list = NULL;
    krb5_principal principal = NULL;
    char *service;
    char *keytab_name = NULL, *principal_name = NULL, *mem_cache = NULL;
    char buf[KT_PATH_MAX], *p;
    size_t j,nprinc = 0;
    int retval = 0;
    krb5_error_code code = 0;

    kparam.context = NULL;

    if (!domain || !strcmp(domain, ""))
        return (1);

    /*
     * Initialise Kerberos
     */

    code = krb5_init_context(&kparam.context);
    if (code) {
        error((char *) "%s| %s: ERROR: Error while initialising Kerberos library : %s\n", LogTime(), PROGRAM, error_message(code));
        retval = 1;
        goto cleanup;
    }
    /*
     * getting default keytab name
     */

    debug((char *) "%s| %s: DEBUG: Get default keytab file name\n", LogTime(), PROGRAM);
    krb5_kt_default_name(kparam.context, buf, KT_PATH_MAX);
    p = strchr(buf, ':');	/* Find the end if "FILE:" */
    if (p)
        ++p;			/* step past : */
    keytab_name = xstrdup(p ? p : buf);
    debug((char *) "%s| %s: DEBUG: Got default keytab file name %s\n", LogTime(), PROGRAM, keytab_name);

    code = krb5_kt_resolve(kparam.context, keytab_name, &keytab);
    if (code) {
        error((char *) "%s| %s: ERROR: Error while resolving keytab %s : %s\n", LogTime(), PROGRAM, keytab_name, error_message(code));
        retval = 1;
        goto cleanup;
    }
    code = krb5_kt_start_seq_get(kparam.context, keytab, &cursor);
    if (code) {
        error((char *) "%s| %s: ERROR: Error while starting keytab scan : %s\n", LogTime(), PROGRAM, error_message(code));
        retval = 1;
        goto cleanup;
    }
    debug((char *) "%s| %s: DEBUG: Get principal name from keytab %s\n", LogTime(), PROGRAM, keytab_name);

    nprinc = 0;
    while ((code = krb5_kt_next_entry(kparam.context, keytab, &entry, &cursor)) == 0) {
        int found = 0;

        principal_list = (krb5_principal *) xrealloc(principal_list, sizeof(krb5_principal) * (nprinc + 1));
        krb5_copy_principal(kparam.context, entry.principal, &principal_list[nprinc++]);
#ifdef HAVE_HEIMDAL_KERBEROS
        debug((char *) "%s| %s: DEBUG: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, entry.principal->realm);
#else
        debug((char *) "%s| %s: DEBUG: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, krb5_princ_realm(kparam.context, entry.principal)->data);
#endif
#ifdef HAVE_HEIMDAL_KERBEROS
        if (!strcasecmp(domain, entry.principal->realm))
#else
        if (!strcasecmp(domain, krb5_princ_realm(kparam.context, entry.principal)->data))
#endif
        {
            code = krb5_unparse_name(kparam.context, entry.principal, &principal_name);
            if (code) {
                error((char *) "%s| %s: ERROR: Error while unparsing principal name : %s\n", LogTime(), PROGRAM, error_message(code));
            } else {
                debug((char *) "%s| %s: DEBUG: Found principal name: %s\n", LogTime(), PROGRAM, principal_name);
                found = 1;
            }
        }
#if defined(HAVE_HEIMDAL_KERBEROS) || ( defined(HAVE_KRB5_KT_FREE_ENTRY) && HAVE_DECL_KRB5_KT_FREE_ENTRY==1)
        code = krb5_kt_free_entry(kparam.context, &entry);
#else
        code = krb5_free_keytab_entry_contents(kparam.context, &entry);
#endif
        if (code) {
            error((char *) "%s| %s: ERROR: Error while freeing keytab entry : %s\n", LogTime(), PROGRAM, error_message(code));
            retval = 1;
            break;
        }
        if (found)
            break;
    }

    if (code && code != KRB5_KT_END) {
        error((char *) "%s| %s: ERROR: Error while scanning keytab : %s\n", LogTime(), PROGRAM, error_message(code));
        retval = 1;
        goto cleanup;
    }
    code = krb5_kt_end_seq_get(kparam.context, keytab, &cursor);
    if (code) {
        error((char *) "%s| %s: ERROR: Error while ending keytab scan : %s\n", LogTime(), PROGRAM, error_message(code));
        retval = 1;
        goto cleanup;
    }
    /*
     * prepare memory credential cache
     */
#if  !defined(HAVE_KRB5_MEMORY_CACHE) || defined(HAVE_SUN_LDAP_SDK)
    mem_cache = (char *) xmalloc(strlen("FILE:/tmp/squid_ldap_") + 16);
    snprintf(mem_cache, strlen("FILE:/tmp/squid_ldap_") + 16, "FILE:/tmp/squid_ldap_%d", (int) getpid());
#else
    mem_cache = (char *) xmalloc(strlen("MEMORY:squid_ldap_") + 16);
    snprintf(mem_cache, strlen("MEMORY:squid_ldap_") + 16, "MEMORY:squid_ldap_%d", (int) getpid());
#endif

    setenv("KRB5CCNAME", mem_cache, 1);
    debug((char *) "%s| %s: DEBUG: Set credential cache to %s\n", LogTime(), PROGRAM, mem_cache);
    code = krb5_cc_resolve(kparam.context, mem_cache, &kparam.cc);
    if (code) {
        error((char *) "%s| %s: ERROR: Error while resolving memory ccache : %s\n", LogTime(), PROGRAM, error_message(code));
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
                debug((char *) "%s| %s: DEBUG: Error while unparsing principal name : %s\n", LogTime(), PROGRAM, error_message(code));
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
                debug((char *) "%s| %s: DEBUG: Error while initialising credentials from keytab : %s\n", LogTime(), PROGRAM, error_message(code));
                goto loop_end;
            }
            code = krb5_cc_initialize(kparam.context, kparam.cc, principal_list[i]);
            if (code) {
                error((char *) "%s| %s: ERROR: Error while initializing memory caches : %s\n", LogTime(), PROGRAM, error_message(code));
                goto loop_end;
            }
            code = krb5_cc_store_cred(kparam.context, kparam.cc, creds);
            if (code) {
                debug((char *) "%s| %s: DEBUG: Error while storing credentials : %s\n", LogTime(), PROGRAM, error_message(code));
                goto loop_end;
            }
            if (creds->server)
                krb5_free_principal(kparam.context, creds->server);
#ifdef HAVE_HEIMDAL_KERBEROS
            service = (char *) xmalloc(strlen("krbtgt") + strlen(domain) + strlen(principal_list[i]->realm) + 3);
            snprintf(service, strlen("krbtgt") + strlen(domain) + strlen(principal_list[i]->realm) + 3, "krbtgt/%s@%s", domain, principal_list[i]->realm);
#else
            service = (char *) xmalloc(strlen("krbtgt") + strlen(domain) + strlen(krb5_princ_realm(kparam.context, principal_list[i])->data) + 3);
            snprintf(service, strlen("krbtgt") + strlen(domain) + strlen(krb5_princ_realm(kparam.context, principal_list[i])->data) + 3, "krbtgt/%s@%s", domain, krb5_princ_realm(kparam.context, principal_list[i])->data);
#endif
            code = krb5_parse_name(kparam.context, service, &creds->server);
            xfree(service);
            if (code) {
                error((char *) "%s| %s: ERROR: Error while initialising TGT credentials : %s\n", LogTime(), PROGRAM, error_message(code));
                goto loop_end;
            }
            code = krb5_get_credentials(kparam.context, 0, kparam.cc, creds, &tgt_creds);
            if (code) {
                debug((char *) "%s| %s: DEBUG: Error while getting tgt : %s\n", LogTime(), PROGRAM, error_message(code));
                goto loop_end;
            } else {
                debug((char *) "%s| %s: DEBUG: Found trusted principal name: %s\n", LogTime(), PROGRAM, principal_name);
                break;
            }

loop_end:
            safe_free(principal_name);
            if (tgt_creds) {
                krb5_free_creds(kparam.context, tgt_creds);
                tgt_creds = NULL;
            }
            if (creds)
                krb5_free_creds(kparam.context, creds);
            creds = NULL;

        }

        if (creds)
            krb5_free_creds(kparam.context, creds);
        creds = NULL;
    }
    if (principal_name) {

        debug((char *) "%s| %s: DEBUG: Got principal name %s\n", LogTime(), PROGRAM, principal_name);
        /*
         * build principal
         */
        code = krb5_parse_name(kparam.context, principal_name, &principal);
        if (code) {
            error((char *) "%s| %s: ERROR: Error while parsing name %s : %s\n", LogTime(), PROGRAM, principal_name, error_message(code));
            retval = 1;
            goto cleanup;
        }
        creds = (krb5_creds *) xmalloc(sizeof(*creds));
        memset(creds, 0, sizeof(*creds));

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
            error((char *) "%s| %s: ERROR: Error while initialising credentials from keytab : %s\n", LogTime(), PROGRAM, error_message(code));
            retval = 1;
            goto cleanup;
        }
        code = krb5_cc_initialize(kparam.context, kparam.cc, principal);
        if (code) {
            error((char *) "%s| %s: ERROR: Error while initializing memory caches : %s\n", LogTime(), PROGRAM, error_message(code));
            retval = 1;
            goto cleanup;
        }
        code = krb5_cc_store_cred(kparam.context, kparam.cc, creds);
        if (code) {
            error((char *) "%s| %s: ERROR: Error while storing credentials : %s\n", LogTime(), PROGRAM, error_message(code));
            retval = 1;
            goto cleanup;
        }
        debug((char *) "%s| %s: DEBUG: Stored credentials\n", LogTime(), PROGRAM);
    } else {
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
