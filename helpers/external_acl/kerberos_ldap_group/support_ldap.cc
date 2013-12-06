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
#include "util.h"

#ifdef HAVE_LDAP

#include "support.h"
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

char *convert_domain_to_bind_path(char *domain);
char *escape_filter(char *filter);
int check_AD(struct main_args *margs, LDAP * ld);
int ldap_set_defaults(LDAP * ld);
int ldap_set_ssl_defaults(struct main_args *margs);
LDAP *tool_ldap_open(struct main_args *margs, char *host, int port, char *ssl);

#define CONNECT_TIMEOUT 2
#define SEARCH_TIMEOUT 30

#define FILTER "(memberuid=%s)"
#define ATTRIBUTE "cn"
#define FILTER_UID "(uid=%s)"
#define FILTER_GID "(&(gidNumber=%s)(objectclass=posixgroup))"
#define ATTRIBUTE_GID "gidNumber"

#define FILTER_AD "(samaccountname=%s)"
#define ATTRIBUTE_AD "memberof"

size_t get_attributes(LDAP * ld, LDAPMessage * res, const char *attribute /* IN */ , char ***out_val /* OUT (caller frees) */ );
int search_group_tree(struct main_args *margs, LDAP * ld, char *bindp, char *ldap_group, char *group, int depth);

#if defined(HAVE_SUN_LDAP_SDK) || defined(HAVE_MOZILLA_LDAP_SDK)
#ifdef HAVE_LDAP_REBINDPROC_CALLBACK

#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
static LDAP_REBINDPROC_CALLBACK ldap_sasl_rebind;

static int LDAP_CALL LDAP_CALLBACK
ldap_sasl_rebind(
    LDAP * ld,
    char **whop,
    char **credp,
    int *methodp,
    int freeit,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    whop = whop;
    credp = credp;
    methodp = methodp;
    freeit = freeit;
    return tool_sasl_bind(ld, cp->dn, cp->pw);
}
#endif

static LDAP_REBINDPROC_CALLBACK ldap_simple_rebind;

static int LDAP_CALL LDAP_CALLBACK
ldap_simple_rebind(
    LDAP * ld,
    char **whop,
    char **credp,
    int *methodp,
    int freeit,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    whop = whop;
    credp = credp;
    methodp = methodp;
    freeit = freeit;
    return ldap_bind_s(ld, cp->dn, cp->pw, LDAP_AUTH_SIMPLE);
}
#elif defined(HAVE_LDAP_REBIND_PROC)
#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
static LDAP_REBIND_PROC ldap_sasl_rebind;

static int
ldap_sasl_rebind(
    LDAP * ld,
    LDAP_CONST char *url,
    ber_tag_t request,
    ber_int_t msgid,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    return tool_sasl_bind(ld, cp->dn, cp->pw);
}
#endif

static LDAP_REBIND_PROC ldap_simple_rebind;

static int
ldap_simple_rebind(
    LDAP * ld,
    LDAP_CONST char *url,
    ber_tag_t request,
    ber_int_t msgid,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    return ldap_bind_s(ld, cp->dn, cp->pw, LDAP_AUTH_SIMPLE);
}

#elif defined(HAVE_LDAP_REBIND_FUNCTION)
#ifndef LDAP_REFERRALS
#define LDAP_REFERRALS
#endif
#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
static LDAP_REBIND_FUNCTION ldap_sasl_rebind;

static int
ldap_sasl_rebind(
    LDAP * ld,
    char **whop,
    char **credp,
    int *methodp,
    int freeit,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    whop = whop;
    credp = credp;
    methodp = methodp;
    freeit = freeit;
    return tool_sasl_bind(ld, cp->dn, cp->pw);
}
#endif

static LDAP_REBIND_FUNCTION ldap_simple_rebind;

static int
ldap_simple_rebind(
    LDAP * ld,
    char **whop,
    char **credp,
    int *methodp,
    int freeit,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    whop = whop;
    credp = credp;
    methodp = methodp;
    freeit = freeit;
    return ldap_bind_s(ld, cp->dn, cp->pw, LDAP_AUTH_SIMPLE);
}
#else
#error "No rebind functione defined"
#endif
#else /* HAVE_SUN_LDAP_SDK */
#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
static LDAP_REBIND_PROC ldap_sasl_rebind;

static int
ldap_sasl_rebind(
    LDAP * ld,
    LDAP_CONST char *url,
    ber_tag_t request,
    ber_int_t msgid,
    void *params)
{
    struct ldap_creds *cp = (struct ldap_creds *) params;
    return tool_sasl_bind(ld, cp->dn, cp->pw);
}
#endif

static LDAP_REBIND_PROC ldap_simple_rebind;

static int
ldap_simple_rebind(
    LDAP * ld,
    LDAP_CONST char *url,
    ber_tag_t request,
    ber_int_t msgid,
    void *params)
{

    struct ldap_creds *cp = (struct ldap_creds *) params;
    return ldap_bind_s(ld, cp->dn, cp->pw, LDAP_AUTH_SIMPLE);
}

#endif
char *
convert_domain_to_bind_path(char *domain)
{
    char *dp, *bindp = NULL, *bp = NULL;
    size_t i = 0;

    if (!domain)
        return NULL;

    for (dp = domain; *dp; ++dp) {
        if (*dp == '.')
            ++i;
    }
    /*
     * add dc= and
     * replace . with ,dc= => new length = old length + #dots * 3 + 3
     */
    bindp = (char *) xmalloc(strlen(domain) + 3 + i * 3 + 1);
    bp = bindp;
    strcpy(bp, "dc=");
    bp += 3;
    for (dp = domain; *dp; ++dp) {
        if (*dp == '.') {
            strcpy(bp, ",dc=");
            bp += 4;
        } else {
            *bp = *dp;
            ++bp;
        }
    }
    *bp = '\0';
    return bindp;
}

char *
escape_filter(char *filter)
{
    char *ldap_filter_esc, *ldf;
    size_t i;

    i = 0;
    for (ldap_filter_esc = filter; *ldap_filter_esc; ++ldap_filter_esc) {
        if ((*ldap_filter_esc == '*') ||
                (*ldap_filter_esc == '(') ||
                (*ldap_filter_esc == ')') ||
                (*ldap_filter_esc == '\\'))
            i = i + 3;
    }

    ldap_filter_esc = (char *) xcalloc(strlen(filter) + i + 1, sizeof(char));
    ldf = ldap_filter_esc;
    for (; *filter; ++filter) {
        if (*filter == '*') {
            strcpy(ldf, "\\2a");
            ldf = ldf + 3;
        } else if (*filter == '(') {
            strcpy(ldf, "\\28");
            ldf = ldf + 3;
        } else if (*filter == ')') {
            strcpy(ldf, "\\29");
            ldf = ldf + 3;
        } else if (*filter == '\\') {
            strcpy(ldf, "\\5c");
            ldf = ldf + 3;
        } else {
            *ldf = *filter;
            ++ldf;
        }
    }
    *ldf = '\0';

    return ldap_filter_esc;
}

int
check_AD(struct main_args *margs, LDAP * ld)
{
    LDAPMessage *res;
    char **attr_value = NULL;
    struct timeval searchtime;
    size_t max_attr = 0;
    int rc = 0;

#define FILTER_SCHEMA "(objectclass=*)"
#define ATTRIBUTE_SCHEMA "schemaNamingContext"
#define FILTER_SAM "(ldapdisplayname=samaccountname)"

    searchtime.tv_sec = SEARCH_TIMEOUT;
    searchtime.tv_usec = 0;

    debug((char *) "%s| %s: DEBUG: Search ldap server with bind path \"\" and filter: %s\n", LogTime(), PROGRAM, FILTER_SCHEMA);
    rc = ldap_search_ext_s(ld, (char *) "", LDAP_SCOPE_BASE, (char *) FILTER_SCHEMA, NULL, 0,
                           NULL, NULL, &searchtime, 0, &res);

    if (rc == LDAP_SUCCESS)
        max_attr = get_attributes(ld, res, ATTRIBUTE_SCHEMA, &attr_value);

    if (max_attr == 1) {
        ldap_msgfree(res);
        debug((char *) "%s| %s: DEBUG: Search ldap server with bind path %s and filter: %s\n", LogTime(), PROGRAM, attr_value[0], FILTER_SAM);
        rc = ldap_search_ext_s(ld, attr_value[0], LDAP_SCOPE_SUBTREE, (char *) FILTER_SAM, NULL, 0,
                               NULL, NULL, &searchtime, 0, &res);
        debug((char *) "%s| %s: DEBUG: Found %d ldap entr%s\n", LogTime(), PROGRAM, ldap_count_entries(ld, res), ldap_count_entries(ld, res) > 1 || ldap_count_entries(ld, res) == 0 ? "ies" : "y");
        if (ldap_count_entries(ld, res) > 0)
            margs->AD = 1;
    } else
        debug((char *) "%s| %s: DEBUG: Did not find ldap entry for subschemasubentry\n", LogTime(), PROGRAM);
    debug((char *) "%s| %s: DEBUG: Determined ldap server %sas an Active Directory server\n", LogTime(), PROGRAM, margs->AD ? "" : "not ");
    /*
     * Cleanup
     */
    if (attr_value) {
        size_t j;
        for (j = 0; j < max_attr; ++j) {
            xfree(attr_value[j]);
        }
        safe_free(attr_value);
    }
    ldap_msgfree(res);
    return rc;
}
int
search_group_tree(struct main_args *margs, LDAP * ld, char *bindp, char *ldap_group, char *group, int depth)
{
    LDAPMessage *res = NULL;
    char **attr_value = NULL;
    size_t max_attr = 0;
    char *filter = NULL;
    char *search_exp = NULL;
    int rc = 0, retval = 0;
    int ldepth;
    char *ldap_filter_esc = NULL;
    struct timeval searchtime;

#define FILTER_GROUP_AD "(&(%s)(objectclass=group))"
#define FILTER_GROUP "(&(memberuid=%s)(objectclass=posixgroup))"

    searchtime.tv_sec = SEARCH_TIMEOUT;
    searchtime.tv_usec = 0;

    if (margs->AD)
        filter = (char *) FILTER_GROUP_AD;
    else
        filter = (char *) FILTER_GROUP;

    ldap_filter_esc = escape_filter(ldap_group);

    search_exp = (char *) xmalloc(strlen(filter) + strlen(ldap_filter_esc) + 1);
    snprintf(search_exp, strlen(filter) + strlen(ldap_filter_esc) + 1, filter, ldap_filter_esc);

    xfree(ldap_filter_esc);

    if (depth > margs->mdepth) {
        debug((char *) "%s| %s: DEBUG: Max search depth reached %d>%d\n", LogTime(), PROGRAM, depth, margs->mdepth);
        xfree(search_exp);
        return 0;
    }
    debug((char *) "%s| %s: DEBUG: Search ldap server with bind path %s and filter : %s\n", LogTime(), PROGRAM, bindp, search_exp);
    rc = ldap_search_ext_s(ld, bindp, LDAP_SCOPE_SUBTREE,
                           search_exp, NULL, 0,
                           NULL, NULL, &searchtime, 0, &res);
    xfree(search_exp);

    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error searching ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        ldap_unbind_s(ld);
        return 0;
    }
    debug((char *) "%s| %s: DEBUG: Found %d ldap entr%s\n", LogTime(), PROGRAM, ldap_count_entries(ld, res), ldap_count_entries(ld, res) > 1 || ldap_count_entries(ld, res) == 0 ? "ies" : "y");

    if (margs->AD)
        max_attr = get_attributes(ld, res, ATTRIBUTE_AD, &attr_value);
    else
        max_attr = get_attributes(ld, res, ATTRIBUTE, &attr_value);

    /*
     * Compare group names
     */
    retval = 0;
    ldepth = depth + 1;
    for (size_t j = 0; j < max_attr; ++j) {
        char *av = NULL;

        /* Compare first CN= value assuming it is the same as the group name itself */
        av = attr_value[j];
        if (!strncasecmp("CN=", av, 3)) {
            char *avp = NULL;
            av += 3;
            if ((avp = strchr(av, ','))) {
                *avp = '\0';
            }
        }
        if (debug_enabled) {
            int n;
            debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" in hex UTF-8 is ", LogTime(), PROGRAM, j + 1, av);
            for (n = 0; av[n] != '\0'; ++n)
                fprintf(stderr, "%02x", (unsigned char) av[n]);
            fprintf(stderr, "\n");
        }
        if (!strcasecmp(group, av)) {
            retval = 1;
            debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" matches group name \"%s\"\n", LogTime(), PROGRAM, j + 1, av, group);
            break;
        } else
            debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" does not match group name \"%s\"\n", LogTime(), PROGRAM, j + 1, av, group);
        /*
         * Do recursive group search
         */
        debug((char *) "%s| %s: DEBUG: Perform recursive group search for group \"%s\"\n", LogTime(), PROGRAM, av);
        av = attr_value[j];
        if (search_group_tree(margs, ld, bindp, av, group, ldepth)) {
            retval = 1;
            if (!strncasecmp("CN=", av, 3)) {
                char *avp = NULL;
                av += 3;
                if ((avp = strchr(av, ','))) {
                    *avp = '\0';
                }
            }
            if (debug_enabled)
                debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" is member of group named \"%s\"\n", LogTime(), PROGRAM, j + 1, av, group);
            else
                break;

        }
    }

    /*
     * Cleanup
     */
    if (attr_value) {
        for (size_t j = 0; j < max_attr; ++j) {
            xfree(attr_value[j]);
        }
        safe_free(attr_value);
    }
    ldap_msgfree(res);

    return retval;
}

int
ldap_set_defaults(LDAP * ld)
{
    int val, rc = 0;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    struct timeval tv;
#endif
    val = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &val);
    if (rc != LDAP_SUCCESS) {
        debug((char *) "%s| %s: DEBUG: Error while setting protocol version: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        return rc;
    }
    rc = ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc != LDAP_SUCCESS) {
        debug((char *) "%s| %s: DEBUG: Error while setting referrals off: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        return rc;
    }
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    tv.tv_sec = CONNECT_TIMEOUT;
    tv.tv_usec = 0;
    rc = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (rc != LDAP_SUCCESS) {
        debug((char *) "%s| %s: DEBUG: Error while setting network timeout: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        return rc;
    }
#endif /* LDAP_OPT_NETWORK_TIMEOUT */
    return LDAP_SUCCESS;
}

int
ldap_set_ssl_defaults(struct main_args *margs)
{
#if defined(HAVE_OPENLDAP) || defined(HAVE_LDAPSSL_CLIENT_INIT)
    int rc = 0;
#endif
#ifdef HAVE_OPENLDAP
    int val;
#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
    char *ssl_certdbpath = NULL;
#endif

#ifdef HAVE_OPENLDAP
    if (!margs->rc_allow) {
        char *ssl_cacertfile = NULL;
        int free_path;
        debug((char *) "%s| %s: DEBUG: Enable server certificate check for ldap server.\n", LogTime(), PROGRAM);
        val = LDAP_OPT_X_TLS_DEMAND;
        rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &val);
        if (rc != LDAP_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting LDAP_OPT_X_TLS_REQUIRE_CERT DEMAND for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            return rc;
        }
        ssl_cacertfile = getenv("TLS_CACERTFILE");
        free_path = 0;
        if (!ssl_cacertfile) {
            ssl_cacertfile = xstrdup("/etc/ssl/certs/cert.pem");
            free_path = 1;
        }
        debug((char *) "%s| %s: DEBUG: Set certificate file for ldap server to %s.(Changeable through setting environment variable TLS_CACERTFILE)\n", LogTime(), PROGRAM, ssl_cacertfile);
        rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ssl_cacertfile);
        if (ssl_cacertfile && free_path) {
            xfree(ssl_cacertfile);
        }
        if (rc != LDAP_OPT_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting LDAP_OPT_X_TLS_CACERTFILE for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            return rc;
        }
    } else {
        debug((char *) "%s| %s: DEBUG: Disable server certificate check for ldap server.\n", LogTime(), PROGRAM);
        val = LDAP_OPT_X_TLS_ALLOW;
        rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &val);
        if (rc != LDAP_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting LDAP_OPT_X_TLS_REQUIRE_CERT ALLOW for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            return rc;
        }
    }
#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
    /*
     *  Solaris SSL ldap calls require path to certificate database
     */
    /*
     * rc = ldapssl_client_init( ssl_certdbpath, NULL );
     * rc = ldapssl_advclientauth_init( ssl_certdbpath, NULL , 0 , NULL, NULL, 0, NULL, 2);
     */
    ssl_certdbpath = getenv("SSL_CERTDBPATH");
    if (!ssl_certdbpath) {
        ssl_certdbpath = xstrdup("/etc/certs");
    }
    debug((char *) "%s| %s: DEBUG: Set certificate database path for ldap server to %s.(Changeable through setting environment variable SSL_CERTDBPATH)\n", LogTime(), PROGRAM, ssl_certdbpath);
    if (!margs->rc_allow) {
        rc = ldapssl_advclientauth_init(ssl_certdbpath, NULL, 0, NULL, NULL, 0, NULL, 2);
    } else {
        rc = ldapssl_advclientauth_init(ssl_certdbpath, NULL, 0, NULL, NULL, 0, NULL, 0);
        debug((char *) "%s| %s: DEBUG: Disable server certificate check for ldap server.\n", LogTime(), PROGRAM);
    }
    xfree(ssl_certdbpath);
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error while setting SSL for ldap server: %s\n", LogTime(), PROGRAM, ldapssl_err2string(rc));
        return rc;
    }
#else
    error((char *) "%s| %s: ERROR: SSL not supported by ldap library\n", LogTime(), PROGRAM);
#endif
    return LDAP_SUCCESS;
}

size_t
get_attributes(LDAP * ld, LDAPMessage * res, const char *attribute, char ***ret_value)
{

    LDAPMessage *msg;
    char **attr_value = NULL;
    size_t max_attr = 0;

    attr_value = *ret_value;
    /*
     * loop over attributes
     */
    debug((char *) "%s| %s: DEBUG: Search ldap entries for attribute : %s\n", LogTime(), PROGRAM, attribute);
    for (msg = ldap_first_entry(ld, res); msg; msg = ldap_next_entry(ld, msg)) {

        BerElement *b;
        char *attr;

        switch (ldap_msgtype(msg)) {

        case LDAP_RES_SEARCH_ENTRY:

            for (attr = ldap_first_attribute(ld, msg, &b); attr;
                    attr = ldap_next_attribute(ld, msg, b)) {
                if (strcasecmp(attr, attribute) == 0) {
                    struct berval **values;
                    int il;

                    if ((values = ldap_get_values_len(ld, msg, attr)) != NULL) {
                        for (il = 0; values[il] != NULL; ++il) {

                            attr_value = (char **) xrealloc(attr_value, (max_attr + 1) * sizeof(char *));
                            if (!attr_value)
                                break;

                            attr_value[max_attr] = (char *) xmalloc(values[il]->bv_len + 1);
                            memcpy(attr_value[max_attr], values[il]->bv_val, values[il]->bv_len);
                            attr_value[max_attr][values[il]->bv_len] = 0;
                            max_attr++;
                        }
                    }
                    ber_bvecfree(values);
                }
                ldap_memfree(attr);
            }
            ber_free(b, 0);
            break;
        case LDAP_RES_SEARCH_REFERENCE:
            debug((char *) "%s| %s: DEBUG: Received a search reference message\n", LogTime(), PROGRAM);
            break;
        case LDAP_RES_SEARCH_RESULT:
            debug((char *) "%s| %s: DEBUG: Received a search result message\n", LogTime(), PROGRAM);
            break;
        default:
            break;
        }
    }

    debug((char *) "%s| %s: DEBUG: %" PRIuSIZE " ldap entr%s found with attribute : %s\n", LogTime(), PROGRAM, max_attr, max_attr > 1 || max_attr == 0 ? "ies" : "y", attribute);

    *ret_value = attr_value;
    return max_attr;
}

/*
 * call to open ldap server with or without SSL
 */
LDAP *
tool_ldap_open(struct main_args * margs, char *host, int port, char *ssl)
{
    LDAP *ld;
#ifdef HAVE_OPENLDAP
    LDAPURLDesc *url = NULL;
    char *ldapuri = NULL;
#endif
    int rc = 0;

    /*
     * Use ldap open here to check if TCP connection is possible. If possible use it.
     * (Not sure if this is the best way)
     */
#ifdef HAVE_OPENLDAP
    url = (LDAPURLDesc *) xmalloc(sizeof(*url));
    memset(url, 0, sizeof(*url));
#ifdef HAVE_LDAP_URL_LUD_SCHEME
    if (ssl)
        url->lud_scheme = xstrdup("ldaps");
    else
        url->lud_scheme = xstrdup("ldap");
#endif
    url->lud_host = xstrdup(host);
    url->lud_port = port;
#ifdef HAVE_LDAP_SCOPE_DEFAULT
    url->lud_scope = LDAP_SCOPE_DEFAULT;
#else
    url->lud_scope = LDAP_SCOPE_SUBTREE;
#endif
#ifdef HAVE_LDAP_URL_DESC2STR
    ldapuri = ldap_url_desc2str(url);
#elif defined(HAVE_LDAP_URL_PARSE)
    rc = ldap_url_parse(ldapuri, &url);
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error while parsing url: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        xfree(ldapuri);
        ldap_free_urldesc(url);
        return NULL;
    }
#else
#error "No URL parsing function"
#endif
    ldap_free_urldesc(url);
    rc = ldap_initialize(&ld, ldapuri);
    xfree(ldapuri);
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error while initialising connection to ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        ldap_unbind(ld);
        ld = NULL;
        return NULL;
    }
#else
    ld = ldap_init(host, port);
#endif
    rc = ldap_set_defaults(ld);
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error while setting default options for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        ldap_unbind(ld);
        ld = NULL;
        return NULL;
    }
    if (ssl) {
        /*
         * Try Start TLS first
         */
        debug((char *) "%s| %s: DEBUG: Set SSL defaults\n", LogTime(), PROGRAM);
        rc = ldap_set_ssl_defaults(margs);
        if (rc != LDAP_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting SSL default options for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            ldap_unbind(ld);
            ld = NULL;
            return NULL;
        }
#ifdef HAVE_OPENLDAP
        /*
         *  Use tls if possible
         */
        rc = ldap_start_tls_s(ld, NULL, NULL);
        if (rc != LDAP_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting start_tls for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            ldap_unbind(ld);
            ld = NULL;
            url = (LDAPURLDesc *) xmalloc(sizeof(*url));
            memset(url, 0, sizeof(*url));
#ifdef HAVE_LDAP_URL_LUD_SCHEME
            url->lud_scheme = xstrdup("ldaps");
#endif
            url->lud_host = xstrdup(host);
            url->lud_port = port;
#ifdef HAVE_LDAP_SCOPE_DEFAULT
            url->lud_scope = LDAP_SCOPE_DEFAULT;
#else
            url->lud_scope = LDAP_SCOPE_SUBTREE;
#endif
#ifdef HAVE_LDAP_URL_DESC2STR
            ldapuri = ldap_url_desc2str(url);
#elif defined(HAVE_LDAP_URL_PARSE)
            rc = ldap_url_parse(ldapuri, &url);
            if (rc != LDAP_SUCCESS) {
                error((char *) "%s| %s: ERROR: Error while parsing url: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
                xfree(ldapuri);
                ldap_free_urldesc(url);
                return NULL;
            }
#else
#error "No URL parsing function"
#endif
            ldap_free_urldesc(url);
            rc = ldap_initialize(&ld, ldapuri);
            xfree(ldapuri);
            if (rc != LDAP_SUCCESS) {
                error((char *) "%s| %s: ERROR: Error while initialising connection to ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
                ldap_unbind(ld);
                ld = NULL;
                return NULL;
            }
            rc = ldap_set_defaults(ld);
            if (rc != LDAP_SUCCESS) {
                error((char *) "%s| %s: ERROR: Error while setting default options for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
                ldap_unbind(ld);
                ld = NULL;
                return NULL;
            }
        }
#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
        ld = ldapssl_init(host, port, 1);
        if (!ld) {
            error((char *) "%s| %s: ERROR: Error while setting SSL for ldap server: %s\n", LogTime(), PROGRAM, ldapssl_err2string(rc));
            ldap_unbind(ld);
            ld = NULL;
            return NULL;
        }
        rc = ldap_set_defaults(ld);
        if (rc != LDAP_SUCCESS) {
            error((char *) "%s| %s: ERROR: Error while setting default options for ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
            ldap_unbind(ld);
            ld = NULL;
            return NULL;
        }
#else
        error((char *) "%s| %s: ERROR: SSL not supported by ldap library\n", LogTime(), PROGRAM);
#endif
    }
    return ld;
}

/*
 * ldap calls to get attribute from Ldap Directory Server
 */
int
get_memberof(struct main_args *margs, char *user, char *domain, char *group)
{
    LDAP *ld = NULL;
    LDAPMessage *res;
#ifndef HAVE_SUN_LDAP_SDK
    int ldap_debug = 0;
#endif
    struct ldap_creds *lcreds = NULL;
    char *bindp = NULL;
    char *filter = NULL;
    char *search_exp;
    struct timeval searchtime;
    int rc = 0, kc = 1;
    int retval;
    char **attr_value = NULL;
    size_t max_attr = 0;
    struct hstruct *hlist = NULL;
    size_t nhosts = 0;
    char *ldap_filter_esc = NULL;

    searchtime.tv_sec = SEARCH_TIMEOUT;
    searchtime.tv_usec = 0;
    /*
     * Fill Kerberos memory cache with credential from keytab for SASL/GSSAPI
     */
    if (domain) {
        debug((char *) "%s| %s: DEBUG: Setup Kerberos credential cache\n", LogTime(), PROGRAM);

#ifdef HAVE_KRB5
        kc = krb5_create_cache(domain);
        if (kc) {
            error((char *) "%s| %s: ERROR: Error during setup of Kerberos credential cache\n", LogTime(), PROGRAM);
        }
#else
        kc = 1;
        debug((char *) "%s| %s: DEBUG: Kerberos is not supported. Use username/passwaord with ldap url instead\n", LogTime(), PROGRAM);
#endif
    }

    if (kc && (!margs->lurl || !margs->luser | !margs->lpass)) {
        /*
         * If Kerberos fails and no url given exit here
         */
        retval = 0;
        goto cleanup;
    }
#ifndef HAVE_SUN_LDAP_SDK
    /*
     * Initialise ldap
     */
    ldap_debug = 127 /* LDAP_DEBUG_TRACE */ ;
    ldap_debug = -1 /* LDAP_DEBUG_ANY */ ;
    ldap_debug = 0;
    (void) ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug);
#endif
    debug((char *) "%s| %s: DEBUG: Initialise ldap connection\n", LogTime(), PROGRAM);

    if (domain && !kc) {
        if (margs->ssl) {
            debug((char *) "%s| %s: DEBUG: Enable SSL to ldap servers\n", LogTime(), PROGRAM);
        }
        debug((char *) "%s| %s: DEBUG: Canonicalise ldap server name for domain %s\n", LogTime(), PROGRAM, domain);
        /*
         * Loop over list of ldap servers of users domain
         */
        nhosts = get_ldap_hostname_list(margs, &hlist, 0, domain);
        for (size_t i = 0; i < nhosts; ++i) {
            int port = 389;
            if (hlist[i].port != -1)
                port = hlist[i].port;
            debug((char *) "%s| %s: DEBUG: Setting up connection to ldap server %s:%d\n", LogTime(), PROGRAM, hlist[i].host, port);

            ld = tool_ldap_open(margs, hlist[i].host, port, margs->ssl);
            if (!ld)
                continue;

            /*
             * ldap bind with SASL/GSSAPI authentication (only possible if a domain was part of the username)
             */

#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
            debug((char *) "%s| %s: DEBUG: Bind to ldap server with SASL/GSSAPI\n", LogTime(), PROGRAM);

            rc = tool_sasl_bind(ld, bindp, margs->ssl);
            if (rc != LDAP_SUCCESS) {
                error((char *) "%s| %s: ERROR: Error while binding to ldap server with SASL/GSSAPI: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
                ldap_unbind(ld);
                ld = NULL;
                continue;
            }
            lcreds = (ldap_creds *) xmalloc(sizeof(struct ldap_creds));
            lcreds->dn = NULL;
            lcreds->pw = margs->ssl ? xstrdup(margs->ssl) : NULL;
            ldap_set_rebind_proc(ld, ldap_sasl_rebind, (char *) lcreds);
            if (ld != NULL) {
                debug((char *) "%s| %s: DEBUG: %s initialised %sconnection to ldap server %s:%d\n", LogTime(), PROGRAM, ld ? "Successfully" : "Failed to", margs->ssl ? "SSL protected " : "", hlist[i].host, port);
                break;
            }
#else
            ldap_unbind(ld);
            ld = NULL;
            error((char *) "%s| %s: ERROR: SASL not supported on system\n", LogTime(), PROGRAM);
            continue;
#endif
        }
        nhosts = free_hostname_list(&hlist, nhosts);
        if (ld == NULL) {
            debug((char *) "%s| %s: DEBUG: Error during initialisation of ldap connection: %s\n", LogTime(), PROGRAM, strerror(errno));
        }
        bindp = convert_domain_to_bind_path(domain);
    }
    if ((!domain || !ld) && margs->lurl && strstr(margs->lurl, "://")) {
        char *hostname;
        char *host;
        int port;
        char *ssl = NULL;
        char *p;
        /*
         * If username does not contain a domain and a url was given then try it
         */
        hostname = strstr(margs->lurl, "://") + 3;
        ssl = strstr(margs->lurl, "ldaps://");
        if (ssl) {
            debug((char *) "%s| %s: DEBUG: Enable SSL to ldap servers\n", LogTime(), PROGRAM);
        }
        debug((char *) "%s| %s: DEBUG: Canonicalise ldap server name %s\n", LogTime(), PROGRAM, hostname);
        /*
         * Loop over list of ldap servers
         */
        host = xstrdup(hostname);
        port = 389;
        if ((p = strchr(host, ':'))) {
            *p = '\0';
            ++p;
            port = atoi(p);
        }
        nhosts = get_hostname_list(&hlist, 0, host);
        xfree(host);
        for (size_t i = 0; i < nhosts; ++i) {

            ld = tool_ldap_open(margs, hlist[i].host, port, ssl);
            if (!ld)
                continue;
            /*
             * ldap bind with username/password authentication
             */

            debug((char *) "%s| %s: DEBUG: Bind to ldap server with Username/Password\n", LogTime(), PROGRAM);
            rc = ldap_simple_bind_s(ld, margs->luser, margs->lpass);
            if (rc != LDAP_SUCCESS) {
                error((char *) "%s| %s: ERROR: Error while binding to ldap server with Username/Password: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
                ldap_unbind(ld);
                ld = NULL;
                continue;
            }
            lcreds = (ldap_creds *) xmalloc(sizeof(struct ldap_creds));
            lcreds->dn = xstrdup(margs->luser);
            lcreds->pw = xstrdup(margs->lpass);
            ldap_set_rebind_proc(ld, ldap_simple_rebind, (char *) lcreds);
            debug((char *) "%s| %s: DEBUG: %s set up %sconnection to ldap server %s:%d\n", LogTime(), PROGRAM, ld ? "Successfully" : "Failed to", ssl ? "SSL protected " : "", hlist[i].host, port);
            break;

        }
        nhosts = free_hostname_list(&hlist, nhosts);
        xfree(bindp);
        if (margs->lbind) {
            bindp = xstrdup(margs->lbind);
        } else {
            bindp = convert_domain_to_bind_path(domain);
        }
    }
    if (ld == NULL) {
        debug((char *) "%s| %s: DEBUG: Error during initialisation of ldap connection: %s\n", LogTime(), PROGRAM, strerror(errno));
        retval = 0;
        goto cleanup;
    }
    /*
     * ldap search for user
     */
    /*
     * Check if server is AD by querying for attribute samaccountname
     */
    margs->AD = 0;
    rc = check_AD(margs, ld);
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error determining ldap server type: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        ldap_unbind(ld);
        ld = NULL;
        retval = 0;
        goto cleanup;
    }
    if (margs->AD)
        filter = (char *) FILTER_AD;
    else
        filter = (char *) FILTER;

    ldap_filter_esc = escape_filter(user);

    search_exp = (char *) xmalloc(strlen(filter) + strlen(ldap_filter_esc) + 1);
    snprintf(search_exp, strlen(filter) + strlen(ldap_filter_esc) + 1, filter, ldap_filter_esc);

    xfree(ldap_filter_esc);

    debug((char *) "%s| %s: DEBUG: Search ldap server with bind path %s and filter : %s\n", LogTime(), PROGRAM, bindp, search_exp);
    rc = ldap_search_ext_s(ld, bindp, LDAP_SCOPE_SUBTREE,
                           search_exp, NULL, 0,
                           NULL, NULL, &searchtime, 0, &res);
    xfree(search_exp);

    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error searching ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
        ldap_unbind(ld);
        ld = NULL;
        retval = 0;
        goto cleanup;
    }
    debug((char *) "%s| %s: DEBUG: Found %d ldap entr%s\n", LogTime(), PROGRAM, ldap_count_entries(ld, res), ldap_count_entries(ld, res) > 1 || ldap_count_entries(ld, res) == 0 ? "ies" : "y");

    if (ldap_count_entries(ld, res) != 0) {

        if (margs->AD)
            max_attr = get_attributes(ld, res, ATTRIBUTE_AD, &attr_value);
        else {
            max_attr = get_attributes(ld, res, ATTRIBUTE, &attr_value);
        }

        /*
         * Compare group names
         */
        retval = 0;
        for (size_t k = 0; k < max_attr; ++k) {
            char *av = NULL;

            /* Compare first CN= value assuming it is the same as the group name itself */
            av = attr_value[k];
            if (!strncasecmp("CN=", av, 3)) {
                char *avp = NULL;
                av += 3;
                if ((avp = strchr(av, ','))) {
                    *avp = '\0';
                }
            }
            if (debug_enabled) {
                debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" in hex UTF-8 is ", LogTime(), PROGRAM, k + 1, av);
                for (unsigned int n = 0; av[n] != '\0'; ++n)
                    fprintf(stderr, "%02x", (unsigned char) av[n]);
                fprintf(stderr, "\n");
            }
            if (!strcasecmp(group, av)) {
                retval = 1;
                if (debug_enabled)
                    debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" matches group name \"%s\"\n", LogTime(), PROGRAM, k + 1, av, group);
                else
                    break;
            } else
                debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " \"%s\" does not match group name \"%s\"\n", LogTime(), PROGRAM, k + 1, av, group);
        }
        /*
         * Do recursive group search for AD only since posixgroups can not contain other groups
         */
        if (!retval && margs->AD) {
            if (debug_enabled && max_attr > 0) {
                debug((char *) "%s| %s: DEBUG: Perform recursive group search\n", LogTime(), PROGRAM);
            }
            for (size_t j = 0; j < max_attr; ++j) {
                char *av = NULL;

                av = attr_value[j];
                if (search_group_tree(margs, ld, bindp, av, group, 1)) {
                    retval = 1;
                    if (!strncasecmp("CN=", av, 3)) {
                        char *avp = NULL;
                        av += 3;
                        if ((avp = strchr(av, ','))) {
                            *avp = '\0';
                        }
                    }
                    if (debug_enabled)
                        debug((char *) "%s| %s: DEBUG: Entry %" PRIuSIZE " group \"%s\" is (in)direct member of group \"%s\"\n", LogTime(), PROGRAM, j + 1, av, group);
                    else
                        break;
                }
            }
        }
        /*
         * Cleanup
         */
        if (attr_value) {
            for (size_t j = 0; j < max_attr; ++j) {
                xfree(attr_value[j]);
            }
            safe_free(attr_value);
        }
        ldap_msgfree(res);
    } else if (ldap_count_entries(ld, res) == 0 && margs->AD) {
        ldap_msgfree(res);
        ldap_unbind(ld);
        ld = NULL;
        retval = 0;
        goto cleanup;
    } else {
        ldap_msgfree(res);
        retval = 0;
    }

    if (!margs->AD && retval == 0) {
        /*
         * Check for primary Group membership
         */
        debug((char *) "%s| %s: DEBUG: Search for primary group membership: \"%s\"\n", LogTime(), PROGRAM, group);
        filter = (char *) FILTER_UID;

        ldap_filter_esc = escape_filter(user);

        search_exp = (char *) xmalloc(strlen(filter) + strlen(ldap_filter_esc) + 1);
        snprintf(search_exp, strlen(filter) + strlen(ldap_filter_esc) + 1, filter, ldap_filter_esc);

        xfree(ldap_filter_esc);

        debug((char *) "%s| %s: DEBUG: Search ldap server with bind path %s and filter: %s\n", LogTime(), PROGRAM, bindp, search_exp);
        rc = ldap_search_ext_s(ld, bindp, LDAP_SCOPE_SUBTREE,
                               search_exp, NULL, 0,
                               NULL, NULL, &searchtime, 0, &res);
        xfree(search_exp);

        debug((char *) "%s| %s: DEBUG: Found %d ldap entr%s\n", LogTime(), PROGRAM, ldap_count_entries(ld, res), ldap_count_entries(ld, res) > 1 || ldap_count_entries(ld, res) == 0 ? "ies" : "y");

        max_attr = get_attributes(ld, res, ATTRIBUTE_GID, &attr_value);

        if (max_attr == 1) {
            char **attr_value_2 = NULL;
            size_t max_attr_2 = 0;

            ldap_msgfree(res);
            filter = (char *) FILTER_GID;

            ldap_filter_esc = escape_filter(attr_value[0]);

            search_exp = (char *) xmalloc(strlen(filter) + strlen(ldap_filter_esc) + 1);
            snprintf(search_exp, strlen(filter) + strlen(ldap_filter_esc) + 1, filter, ldap_filter_esc);

            xfree(ldap_filter_esc);

            debug((char *) "%s| %s: DEBUG: Search ldap server with bind path %s and filter: %s\n", LogTime(), PROGRAM, bindp, search_exp);
            rc = ldap_search_ext_s(ld, bindp, LDAP_SCOPE_SUBTREE,
                                   search_exp, NULL, 0,
                                   NULL, NULL, &searchtime, 0, &res);
            xfree(search_exp);

            max_attr_2 = get_attributes(ld, res, ATTRIBUTE, &attr_value_2);
            /*
             * Compare group names
             */
            retval = 0;
            if (max_attr_2 == 1) {
                /* Compare first CN= value assuming it is the same as the group name itself */
                char *av = attr_value_2[0];
                if (!strcasecmp(group, av)) {
                    retval = 1;
                    debug((char *) "%s| %s: DEBUG: \"%s\" matches group name \"%s\"\n", LogTime(), PROGRAM, av, group);
                } else
                    debug((char *) "%s| %s: DEBUG: \"%s\" does not match group name \"%s\"\n", LogTime(), PROGRAM, av, group);

            }
            /*
             * Cleanup
             */
            if (attr_value_2) {
                size_t j;
                for (j = 0; j < max_attr_2; ++j) {
                    xfree(attr_value_2[j]);
                }
                safe_free(attr_value_2);
            }
            ldap_msgfree(res);

            debug((char *) "%s| %s: DEBUG: Users primary group %s %s\n", LogTime(), PROGRAM, retval ? "matches" : "does not match", group);

        } else {
            ldap_msgfree(res);
            debug((char *) "%s| %s: DEBUG: Did not find ldap entry for group %s\n", LogTime(), PROGRAM, group);
        }
        /*
         * Cleanup
         */
        if (attr_value) {
            for (size_t j = 0; j < max_attr; ++j) {
                xfree(attr_value[j]);
            }
            safe_free(attr_value);
        }
    }
    rc = ldap_unbind(ld);
    ld = NULL;
    if (rc != LDAP_SUCCESS) {
        error((char *) "%s| %s: ERROR: Error unbind ldap server: %s\n", LogTime(), PROGRAM, ldap_err2string(rc));
    }
    debug((char *) "%s| %s: DEBUG: Unbind ldap server\n", LogTime(), PROGRAM);
cleanup:
#ifdef HAVE_KRB5
    if (domain)
        krb5_cleanup();
#endif
    if (lcreds) {
        xfree(lcreds->dn);
        xfree(lcreds->pw);
        xfree(lcreds);
    }
    xfree(bindp);
    return (retval);
}
#endif
