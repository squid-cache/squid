/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */

#include "squid.h"
#include "rfc1738.h"

#if HAVE_GSSAPI

#include "negotiate_kerberos.h"

#if HAVE_SYS_STAT_H
#include "sys/stat.h"
#endif
#if HAVE_UNISTD_H
#include "unistd.h"
#endif

#if HAVE_KRB5_MEMORY_KEYTAB
typedef struct _krb5_kt_list {
    struct _krb5_kt_list *next;
    krb5_keytab_entry *entry;
} *krb5_kt_list;
krb5_kt_list ktlist = NULL;

krb5_error_code krb5_free_kt_list(krb5_context context, krb5_kt_list kt_list);
krb5_error_code krb5_write_keytab(krb5_context context,
                                  krb5_kt_list kt_list,
                                  char *name);
krb5_error_code krb5_read_keytab(krb5_context context,
                                 char *name,
                                 krb5_kt_list *kt_list);
#endif /* HAVE_KRB5_MEMORY_KEYTAB */

int
check_k5_err(krb5_context context, const char *function, krb5_error_code code)
{

    if (code && code != KRB5_KT_END) {
        const char *errmsg;
        errmsg = krb5_get_error_message(context, code);
        debug((char *) "%s| %s: ERROR: %s failed: %s\n", LogTime(), PROGRAM, function, errmsg);
        fprintf(stderr, "%s| %s: ERROR: %s: %s\n", LogTime(), PROGRAM, function, errmsg);
#if HAVE_KRB5_FREE_ERROR_MESSAGE
        krb5_free_error_message(context, errmsg);
#elif HAVE_KRB5_FREE_ERROR_STRING
        krb5_free_error_string(context, (char *)errmsg);
#else
        xfree(errmsg);
#endif
    }
    return code;
}

char *
gethost_name(void)
{
    /*
     * char hostname[sysconf(_SC_HOST_NAME_MAX)];
     */
    char hostname[1024];
    struct addrinfo *hres = NULL, *hres_list;
    int rc, count;

    rc = gethostname(hostname, sizeof(hostname)-1);
    if (rc) {
        debug((char *) "%s| %s: ERROR: resolving hostname '%s' failed\n", LogTime(), PROGRAM, hostname);
        fprintf(stderr, "%s| %s: ERROR: resolving hostname '%s' failed\n",
                LogTime(), PROGRAM, hostname);
        return NULL;
    }
    rc = getaddrinfo(hostname, NULL, NULL, &hres);
    if (rc != 0 || hres == NULL ) {
        debug((char *) "%s| %s: ERROR: resolving hostname with getaddrinfo: %s failed\n",
              LogTime(), PROGRAM, gai_strerror(rc));
        fprintf(stderr,
                "%s| %s: ERROR: resolving hostname with getaddrinfo: %s failed\n",
                LogTime(), PROGRAM, gai_strerror(rc));
        return NULL;
    }
    hres_list = hres;
    count = 0;
    while (hres_list) {
        ++count;
        hres_list = hres_list->ai_next;
    }
    rc = getnameinfo(hres->ai_addr, hres->ai_addrlen, hostname,
                     sizeof(hostname), NULL, 0, 0);
    if (rc != 0) {
        debug((char *) "%s| %s: ERROR: resolving ip address with getnameinfo: %s failed\n",
              LogTime(), PROGRAM, gai_strerror(rc));
        fprintf(stderr,
                "%s| %s: ERROR: resolving ip address with getnameinfo: %s failed\n",
                LogTime(), PROGRAM, gai_strerror(rc));
        freeaddrinfo(hres);
        return NULL;
    }
    freeaddrinfo(hres);
    hostname[sizeof(hostname)-1] = '\0';
    return (xstrdup(hostname));
}

int
check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
              const char *function, int log, int sout)
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
        debug((char *) "%s| %s: ERROR: %s failed: %s\n", LogTime(), PROGRAM, function, buf);
        if (sout)
            fprintf(stdout, "BH %s failed: %s\n", function, buf);
        if (log)
            fprintf(stderr, "%s| %s: INFO: User not authenticated\n", LogTime(),
                    PROGRAM);
        return (1);
    }
    return (0);
}

#if HAVE_KRB5_MEMORY_KEYTAB
/*
 * Free a kt_list
 */
krb5_error_code krb5_free_kt_list(krb5_context context, krb5_kt_list list)
{
    krb5_kt_list lp = list;

    while (lp) {
#if USE_HEIMDAL_KRB5 || ( HAVE_KRB5_KT_FREE_ENTRY && HAVE_DECL_KRB5_KT_FREE_ENTRY )
        krb5_error_code  retval = krb5_kt_free_entry(context, lp->entry);
#else
        krb5_error_code  retval = krb5_free_keytab_entry_contents(context, lp->entry);
#endif
        safe_free(lp->entry);
        if (check_k5_err(context, "krb5_kt_free_entry", retval))
            return retval;
        krb5_kt_list prev = lp;
        lp = lp->next;
        xfree(prev);
    }
    return 0;
}
/*
 * Read in a keytab and append it to list.  If list starts as NULL,
 * allocate a new one if necessary.
 */
krb5_error_code krb5_read_keytab(krb5_context context, char *name, krb5_kt_list *list)
{
    krb5_kt_list lp = NULL, tail = NULL, back = NULL;
    krb5_keytab kt;
    krb5_keytab_entry *entry;
    krb5_kt_cursor cursor;
    krb5_error_code retval = 0;

    if (*list) {
        /* point lp at the tail of the list */
        for (lp = *list; lp->next; lp = lp->next);
        back = lp;
    }
    retval = krb5_kt_resolve(context, name, &kt);
    if (check_k5_err(context, "krb5_kt_resolve", retval))
        return retval;
    retval = krb5_kt_start_seq_get(context, kt, &cursor);
    if (check_k5_err(context, "krb5_kt_start_seq_get", retval))
        goto close_kt;
    for (;;) {
        entry = (krb5_keytab_entry *)xcalloc(1, sizeof (krb5_keytab_entry));
        if (!entry) {
            retval = ENOMEM;
            debug((char *) "%s| %s: ERROR: krb5_read_keytab failed: %s\n",
                  LogTime(), PROGRAM, strerror(retval));
            fprintf(stderr, "%s| %s: ERROR: krb5_read_keytab: %s\n",
                    LogTime(), PROGRAM, strerror(retval));
            break;
        }
        memset(entry, 0, sizeof (*entry));
        retval = krb5_kt_next_entry(context, kt, entry, &cursor);
        if (check_k5_err(context, "krb5_kt_next_entry", retval))
            break;

        if (!lp) {              /* if list is empty, start one */
            lp = (krb5_kt_list)xmalloc(sizeof (*lp));
            if (!lp) {
                retval = ENOMEM;
                debug((char *) "%s| %s: ERROR: krb5_read_keytab failed: %s\n",
                      LogTime(), PROGRAM, strerror(retval));
                fprintf(stderr, "%s| %s: ERROR: krb5_read_keytab: %s\n",
                        LogTime(), PROGRAM, strerror(retval));
                break;
            }
        } else {
            lp->next = (krb5_kt_list)xmalloc(sizeof (*lp));
            if (!lp->next) {
                retval = ENOMEM;
                debug((char *) "%s| %s: ERROR: krb5_read_keytab failed: %s\n",
                      LogTime(), PROGRAM, strerror(retval));
                fprintf(stderr, "%s| %s: ERROR: krb5_read_keytab: %s\n",
                        LogTime(), PROGRAM, strerror(retval));
                break;
            }
            lp = lp->next;
        }
        if (!tail)
            tail = lp;
        lp->next = NULL;
        lp->entry = entry;
    }
    xfree(entry);
    if (retval) {
        if (retval == KRB5_KT_END)
            retval = 0;
        else {
            krb5_free_kt_list(context, tail);
            tail = NULL;
            if (back)
                back->next = NULL;
        }
    }
    if (!*list)
        *list = tail;
    krb5_kt_end_seq_get(context, kt, &cursor);
close_kt:
    krb5_kt_close(context, kt);
    return retval;
}

/*
 * Takes a kt_list and writes it to the named keytab.
 */
krb5_error_code krb5_write_keytab(krb5_context context, krb5_kt_list list, char *name)
{
    krb5_keytab kt;
    char ktname[MAXPATHLEN+sizeof("MEMORY:")+1];
    krb5_error_code retval = 0;

    snprintf(ktname, sizeof(ktname), "%s", name);
    retval = krb5_kt_resolve(context, ktname, &kt);
    if (retval)
        return retval;
    for (krb5_kt_list lp = list; lp; lp = lp->next) {
        retval = krb5_kt_add_entry(context, kt, lp->entry);
        if (retval)
            break;
    }
    /*
     *     krb5_kt_close(context, kt);
     */
    return retval;
}
#endif /* HAVE_KRB5_MEMORY_KEYTAB */

int
main(int argc, char *const argv[])
{
    char buf[MAX_AUTHTOKEN_LEN];
    char *c, *p;
    char *user = NULL;
    char *rfc_user = NULL;
#if HAVE_PAC_SUPPORT
    char ad_groups[MAX_PAC_GROUP_SIZE];
    char *ag=NULL;
    krb5_pac pac;
#if USE_HEIMDAL_KRB5
    gss_buffer_desc data_set = GSS_C_EMPTY_BUFFER;
#else
    gss_buffer_desc type_id = GSS_C_EMPTY_BUFFER;
#endif
#endif
    krb5_context context = NULL;
    krb5_error_code ret;
    long length = 0;
    static int err = 0;
    int opt, log = 0, norealm = 0;
    OM_uint32 ret_flags = 0, spnego_flag = 0;
    char *service_name = (char *) "HTTP", *host_name = NULL;
    char *token = NULL;
    char *service_principal = NULL;
    char *keytab_name = NULL;
    char *keytab_name_env = NULL;
    char default_keytab[MAXPATHLEN];
#if HAVE_KRB5_MEMORY_KEYTAB
    char *memory_keytab_name = NULL;
#endif
    char *rcache_type = NULL;
    char *rcache_type_env = NULL;
    char *rcache_dir = NULL;
    char *rcache_dir_env = NULL;
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_name_t server_name = GSS_C_NO_NAME;
    gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    const unsigned char *kerberosToken = NULL;
    const unsigned char *spnegoToken = NULL;
    size_t spnegoTokenLength = 0;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    while (-1 != (opt = getopt(argc, argv, "dirs:k:c:t:"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'i':
            log = 1;
            break;
        case 'r':
            norealm = 1;
            break;
        case 'k':
#if HAVE_SYS_STAT_H
            struct stat fstat;
            char *ktp;
#endif
            if (optarg)
                keytab_name = xstrdup(optarg);
            else {
                fprintf(stderr, "ERROR: keytab file not given\n");
                exit(1);
            }
            /*
             * Some sanity checks
             */
#if HAVE_SYS_STAT_H
            if ((ktp=strchr(keytab_name,':')))
                ktp++;
            else
                ktp=keytab_name;
            if (stat((const char*)ktp, &fstat)) {
                if (ENOENT == errno)
                    fprintf(stderr, "ERROR: keytab file %s does not exist\n",keytab_name);
                else
                    fprintf(stderr, "ERROR: Error %s during stat of keytab file %s\n",strerror(errno),keytab_name);
                exit(1);
            } else if (!S_ISREG(fstat.st_mode)) {
                fprintf(stderr, "ERROR: keytab file %s is not a file\n",keytab_name);
                exit(1);
            }
#endif
#if HAVE_UNISTD_H
            if (access(ktp, R_OK)) {
                fprintf(stderr, "ERROR: keytab file %s is not accessible\n",keytab_name);
                exit(1);
            }
#endif
            break;
        case 'c':
#if HAVE_SYS_STAT_H
            struct stat dstat;
#endif
            if (optarg)
                rcache_dir = xstrdup(optarg);
            else {
                fprintf(stderr, "ERROR: replay cache directory not given\n");
                exit(1);
            }
            /*
             * Some sanity checks
             */
#if HAVE_SYS_STAT_H
            if (stat((const char*)rcache_dir, &dstat)) {
                if (ENOENT == errno)
                    fprintf(stderr, "ERROR: replay cache directory %s does not exist\n",rcache_dir);
                else
                    fprintf(stderr, "ERROR: Error %s during stat of replay cache directory %s\n",strerror(errno),rcache_dir);
                exit(1);
            } else if (!S_ISDIR(dstat.st_mode)) {
                fprintf(stderr, "ERROR: replay cache directory %s is not a directory\n",rcache_dir);
                exit(1);
            }
#endif
#if HAVE_UNISTD_H
            if (access(rcache_dir, W_OK)) {
                fprintf(stderr, "ERROR: replay cache directory %s is not accessible\n",rcache_dir);
                exit(1);
            }
#endif
            break;
        case 't':
            if (optarg)
                rcache_type = xstrdup(optarg);
            else {
                fprintf(stderr, "ERROR: replay cache type not given\n");
                exit(1);
            }
            break;
        case 's':
            if (optarg)
                service_principal = xstrdup(optarg);
            else {
                fprintf(stderr, "ERROR: service principal not given\n");
                exit(1);
            }
            break;
        default:
            fprintf(stderr, "Usage: \n");
            fprintf(stderr, "squid_kerb_auth [-d] [-i] [-s SPN] [-k keytab] [-c rcdir] [-t rctype]\n");
            fprintf(stderr, "-d full debug\n");
            fprintf(stderr, "-i informational messages\n");
            fprintf(stderr, "-r remove realm from username\n");
            fprintf(stderr, "-s service principal name\n");
            fprintf(stderr, "-k keytab name\n");
            fprintf(stderr, "-c replay cache directory\n");
            fprintf(stderr, "-t replay cache type\n");
            fprintf(stderr,
                    "The SPN can be set to GSS_C_NO_NAME to allow any entry from keytab\n");
            fprintf(stderr, "default SPN is HTTP/fqdn@DEFAULT_REALM\n");
            exit(0);
        }
    }

    debug((char *) "%s| %s: INFO: Starting version %s\n", LogTime(), PROGRAM, SQUID_KERB_AUTH_VERSION);
    if (service_principal && strcasecmp(service_principal, "GSS_C_NO_NAME")) {
        if (!strstr(service_principal,"HTTP/")) {
            debug((char *) "%s| %s: WARN: service_principal %s does not start with HTTP/\n",
                  LogTime(), PROGRAM, service_principal);
        }
        service.value = service_principal;
        service.length = strlen((char *) service.value);
    } else {
        host_name = gethost_name();
        if (!host_name) {
            fprintf(stderr,
                    "%s| %s: FATAL: Local hostname could not be determined. Please specify the service principal\n",
                    LogTime(), PROGRAM);
            fprintf(stdout, "BH hostname error\n");
            exit(-1);
        }
        service.value = xmalloc(strlen(service_name) + strlen(host_name) + 2);
        snprintf((char *) service.value, strlen(service_name) + strlen(host_name) + 2,
                 "%s@%s", service_name, host_name);
        service.length = strlen((char *) service.value);
        xfree(host_name);
    }

    if (rcache_type) {
        rcache_type_env = (char *) xmalloc(strlen("KRB5RCACHETYPE=")+strlen(rcache_type)+1);
        strcpy(rcache_type_env, "KRB5RCACHETYPE=");
        strcat(rcache_type_env, rcache_type);
        putenv(rcache_type_env);
        debug((char *) "%s| %s: INFO: Setting replay cache type to %s\n",
              LogTime(), PROGRAM, rcache_type);
    }

    if (rcache_dir) {
        rcache_dir_env = (char *) xmalloc(strlen("KRB5RCACHEDIR=")+strlen(rcache_dir)+1);
        strcpy(rcache_dir_env, "KRB5RCACHEDIR=");
        strcat(rcache_dir_env, rcache_dir);
        putenv(rcache_dir_env);
        debug((char *) "%s| %s: INFO: Setting replay cache directory to %s\n",
              LogTime(), PROGRAM, rcache_dir);
    }

    if (keytab_name) {
        keytab_name_env = (char *) xmalloc(strlen("KRB5_KTNAME=")+strlen(keytab_name)+1);
        strcpy(keytab_name_env, "KRB5_KTNAME=");
        strcat(keytab_name_env, keytab_name);
        putenv(keytab_name_env);
    } else {
        keytab_name_env = getenv("KRB5_KTNAME");
        if (!keytab_name_env) {
            ret = krb5_init_context(&context);
            if (!check_k5_err(context, "krb5_init_context", ret)) {
                krb5_kt_default_name(context, default_keytab, MAXPATHLEN);
            }
            keytab_name = xstrdup(default_keytab);
            krb5_free_context(context);
        } else
            keytab_name = xstrdup(keytab_name_env);
    }
    debug((char *) "%s| %s: INFO: Setting keytab to %s\n", LogTime(), PROGRAM, keytab_name);
#if HAVE_KRB5_MEMORY_KEYTAB
    ret = krb5_init_context(&context);
    if (!check_k5_err(context, "krb5_init_context", ret)) {
        memory_keytab_name = (char *)xmalloc(strlen("MEMORY:negotiate_kerberos_auth_")+16);
        snprintf(memory_keytab_name, strlen("MEMORY:negotiate_kerberos_auth_")+16,
                 "MEMORY:negotiate_kerberos_auth_%d", (unsigned int) getpid());
        ret = krb5_read_keytab(context, keytab_name, &ktlist);
        if (check_k5_err(context, "krb5_read_keytab", ret)) {
            debug((char *) "%s| %s: ERROR: Reading keytab %s into list failed\n",
                  LogTime(), PROGRAM, keytab_name);
        } else {
            ret = krb5_write_keytab(context, ktlist, memory_keytab_name);
            if (check_k5_err(context, "krb5_write_keytab", ret)) {
                debug((char *) "%s| %s: ERROR: Writing list into keytab %s\n",
                      LogTime(), PROGRAM, memory_keytab_name);
            } else {
                keytab_name_env = (char *) xmalloc(strlen("KRB5_KTNAME=")+strlen(memory_keytab_name)+1);
                strcpy(keytab_name_env, "KRB5_KTNAME=");
                strcat(keytab_name_env, memory_keytab_name);
                putenv(keytab_name_env);
                xfree(keytab_name);
                keytab_name = xstrdup(memory_keytab_name);
                debug((char *) "%s| %s: INFO: Changed keytab to %s\n",
                      LogTime(), PROGRAM, memory_keytab_name);
            }
        }
        ret = krb5_free_kt_list(context,ktlist);
        if (check_k5_err(context, "krb5_free_kt_list", ret)) {
            debug((char *) "%s| %s: ERROR: Freeing list failed\n",
                  LogTime(), PROGRAM);
        }
    }
    krb5_free_context(context);
#endif
#ifdef HAVE_HEIMDAL_KERBEROS
    gsskrb5_register_acceptor_identity(keytab_name);
#endif
    while (1) {
        if (fgets(buf, sizeof(buf) - 1, stdin) == NULL) {
            if (ferror(stdin)) {
                debug((char *) "%s| %s: FATAL: fgets() failed! dying..... errno=%d (%s)\n",
                      LogTime(), PROGRAM, ferror(stdin),
                      strerror(ferror(stdin)));

                fprintf(stdout, "BH input error\n");
                exit(1);    /* BIIG buffer */
            }
            fprintf(stdout, "BH input error\n");
            exit(0);
        }
        c = (char *) memchr(buf, '\n', sizeof(buf) - 1);
        if (c) {
            *c = '\0';
            length = c - buf;
        } else {
            err = 1;
        }
        if (err) {
            debug((char *) "%s| %s: ERROR: Oversized message\n", LogTime(), PROGRAM);
            fprintf(stdout, "BH Oversized message\n");
            err = 0;
            continue;
        }
        debug((char *) "%s| %s: DEBUG: Got '%s' from squid (length: %ld).\n", LogTime(), PROGRAM, buf, length);

        if (buf[0] == '\0') {
            debug((char *) "%s| %s: ERROR: Invalid request\n", LogTime(), PROGRAM);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }
        if (strlen(buf) < 2) {
            debug((char *) "%s| %s: ERROR: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }
        if (!strncmp(buf, "QQ", 2)) {
            gss_release_buffer(&minor_status, &input_token);
            gss_release_buffer(&minor_status, &output_token);
            gss_release_buffer(&minor_status, &service);
            gss_release_cred(&minor_status, &server_creds);
            if (server_name)
                gss_release_name(&minor_status, &server_name);
            if (client_name)
                gss_release_name(&minor_status, &client_name);
            if (gss_context != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&minor_status, &gss_context, NULL);
            if (kerberosToken) {
                /* Allocated by parseNegTokenInit, but no matching free function exists.. */
                if (!spnego_flag)
                    xfree(kerberosToken);
            }
            if (spnego_flag) {
                /* Allocated by makeNegTokenTarg, but no matching free function exists.. */
                xfree(spnegoToken);
            }
            xfree(token);
            fprintf(stdout, "BH quit command\n");
            exit(0);
        }
        if (strncmp(buf, "YR", 2) && strncmp(buf, "KK", 2)) {
            debug((char *) "%s| %s: ERROR: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }
        if (!strncmp(buf, "YR", 2)) {
            if (gss_context != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&minor_status, &gss_context, NULL);
            gss_context = GSS_C_NO_CONTEXT;
        }
        if (strlen(buf) <= 3) {
            debug((char *) "%s| %s: ERROR: Invalid negotiate request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid negotiate request\n");
            continue;
        }
        const char *b64Token = buf+3;
        const size_t srcLen = strlen(buf+3);
        input_token.length = BASE64_DECODE_LENGTH(srcLen);
        debug((char *) "%s| %s: DEBUG: Decode '%s' (decoded length estimate: %d).\n",
              LogTime(), PROGRAM, b64Token, (int) input_token.length);
        input_token.value = xmalloc(input_token.length);

        struct base64_decode_ctx ctx;
        base64_decode_init(&ctx);
        size_t dstLen = 0;
        if (!base64_decode_update(&ctx, &dstLen, static_cast<uint8_t*>(input_token.value), srcLen, b64Token) ||
                !base64_decode_final(&ctx)) {
            debug((char *) "%s| %s: ERROR: Invalid base64 token [%s]\n", LogTime(), PROGRAM, b64Token);
            fprintf(stdout, "BH Invalid negotiate request token\n");
            continue;
        }
        input_token.length = dstLen;

        if ((input_token.length >= sizeof ntlmProtocol + 1) &&
                (!memcmp(input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
            debug((char *) "%s| %s: WARNING: received type %d NTLM token\n",
                  LogTime(), PROGRAM,
                  (int) *((unsigned char *) input_token.value +
                          sizeof ntlmProtocol));
            fprintf(stdout, "BH received type %d NTLM token\n",
                    (int) *((unsigned char *) input_token.value +
                            sizeof ntlmProtocol));
            goto cleanup;
        }
        if (service_principal) {
            if (strcasecmp(service_principal, "GSS_C_NO_NAME")) {
                major_status = gss_import_name(&minor_status, &service,
                                               (gss_OID) GSS_C_NULL_OID, &server_name);

            } else {
                server_name = GSS_C_NO_NAME;
                major_status = GSS_S_COMPLETE;
                minor_status = 0;
            }
        } else {
            major_status = gss_import_name(&minor_status, &service,
                                           gss_nt_service_name, &server_name);
        }

        if (check_gss_err(major_status, minor_status, "gss_import_name()", log, 1))
            goto cleanup;

        major_status =
            gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds, NULL, NULL);
        if (check_gss_err(major_status, minor_status, "gss_acquire_cred()", log, 1))
            goto cleanup;

        major_status = gss_accept_sec_context(&minor_status,
                                              &gss_context,
                                              server_creds,
                                              &input_token,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              &client_name, NULL, &output_token, &ret_flags, NULL, NULL);

        if (output_token.length) {
            spnegoToken = (const unsigned char *) output_token.value;
            spnegoTokenLength = output_token.length;
            token = (char *) xmalloc((size_t)base64_encode_len(spnegoTokenLength));
            if (token == NULL) {
                debug((char *) "%s| %s: ERROR: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }
            struct base64_encode_ctx tokCtx;
            base64_encode_init(&tokCtx);
            size_t blen = base64_encode_update(&tokCtx, token, spnegoTokenLength, reinterpret_cast<const uint8_t*>(spnegoToken));
            blen += base64_encode_final(&tokCtx, token+blen);
            token[blen] = '\0';

            if (check_gss_err(major_status, minor_status, "gss_accept_sec_context()", log, 1))
                goto cleanup;
            if (major_status & GSS_S_CONTINUE_NEEDED) {
                debug((char *) "%s| %s: INFO: continuation needed\n", LogTime(), PROGRAM);
                fprintf(stdout, "TT token=%s\n", token);
                goto cleanup;
            }
            gss_release_buffer(&minor_status, &output_token);
            major_status =
                gss_display_name(&minor_status, client_name, &output_token,
                                 NULL);

            if (check_gss_err(major_status, minor_status, "gss_display_name()", log, 1))
                goto cleanup;
            user = (char *) xmalloc(output_token.length + 1);
            if (user == NULL) {
                debug((char *) "%s| %s: ERROR: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }
            memcpy(user, output_token.value, output_token.length);
            user[output_token.length] = '\0';
            if (norealm && (p = strchr(user, '@')) != NULL) {
                *p = '\0';
            }

#if HAVE_PAC_SUPPORT
            ret = krb5_init_context(&context);
            if (!check_k5_err(context, "krb5_init_context", ret)) {
#if USE_HEIMDAL_KRB5
#define ADWIN2KPAC 128
                major_status = gsskrb5_extract_authz_data_from_sec_context(&minor_status,
                               gss_context, ADWIN2KPAC, &data_set);
                if (!check_gss_err(major_status, minor_status,
                                   "gsskrb5_extract_authz_data_from_sec_context()", log, 0)) {
                    ret = krb5_pac_parse(context, data_set.value, data_set.length, &pac);
                    gss_release_buffer(&minor_status, &data_set);
                    if (!check_k5_err(context, "krb5_pac_parse", ret)) {
                        ag = get_ad_groups((char *)&ad_groups, context, pac);
                        krb5_pac_free(context, pac);
                    }
                    krb5_free_context(context);
                }
#else
                type_id.value = (void *)"mspac";
                type_id.length = strlen((char *)type_id.value);
#define KRB5PACLOGONINFO        1
                major_status = gss_map_name_to_any(&minor_status, client_name, KRB5PACLOGONINFO, &type_id, (gss_any_t *)&pac);
                if (!check_gss_err(major_status, minor_status, "gss_map_name_to_any()", log, 0)) {
                    ag = get_ad_groups((char *)&ad_groups,context, pac);
                }
                (void)gss_release_any_name_mapping(&minor_status, client_name, &type_id, (gss_any_t *)&pac);
                krb5_free_context(context);
#endif
            }
            if (ag) {
                debug((char *) "%s| %s: DEBUG: Groups %s\n", LogTime(), PROGRAM, ag);
            }
#endif
            rfc_user = rfc1738_escape(user);
#if HAVE_PAC_SUPPORT
            fprintf(stdout, "OK token=%s user=%s %s\n", token, rfc_user, ag?ag:"group=");
#else
            fprintf(stdout, "OK token=%s user=%s\n", token, rfc_user);
#endif
            debug((char *) "%s| %s: DEBUG: OK token=%s user=%s\n", LogTime(), PROGRAM, token, rfc_user);
            if (log)
                fprintf(stderr, "%s| %s: INFO: User %s authenticated\n", LogTime(),
                        PROGRAM, rfc_user);
            goto cleanup;
        } else {
            if (check_gss_err(major_status, minor_status, "gss_accept_sec_context()", log, 1))
                goto cleanup;
            if (major_status & GSS_S_CONTINUE_NEEDED) {
                debug((char *) "%s| %s: INFO: continuation needed\n", LogTime(), PROGRAM);
                fprintf(stdout, "ERR token=%s\n", token);
                goto cleanup;
            }
            gss_release_buffer(&minor_status, &output_token);
            major_status =
                gss_display_name(&minor_status, client_name, &output_token,
                                 NULL);

            if (check_gss_err(major_status, minor_status, "gss_display_name()", log, 1))
                goto cleanup;
            /*
             *  Return dummy token AA. May need an extra return tag then AF
             */
            user = (char *) xmalloc(output_token.length + 1);
            if (user == NULL) {
                debug((char *) "%s| %s: ERROR: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }
            memcpy(user, output_token.value, output_token.length);
            user[output_token.length] = '\0';
            if (norealm && (p = strchr(user, '@')) != NULL) {
                *p = '\0';
            }
            rfc_user = rfc1738_escape(user);
#if HAVE_PAC_SUPPORT
            fprintf(stdout, "OK token=%s user=%s %s\n", "AA==", rfc_user, ag?ag:"group=");
#else
            fprintf(stdout, "OK token=%s user=%s\n", "AA==", rfc_user);
#endif
            debug((char *) "%s| %s: DEBUG: OK token=%s user=%s\n", LogTime(), PROGRAM, "AA==", rfc_user);
            if (log)
                fprintf(stderr, "%s| %s: INFO: User %s authenticated\n", LogTime(),
                        PROGRAM, rfc_user);
        }
cleanup:
        gss_release_buffer(&minor_status, &input_token);
        gss_release_buffer(&minor_status, &output_token);
        gss_release_cred(&minor_status, &server_creds);
        if (server_name)
            gss_release_name(&minor_status, &server_name);
        if (client_name)
            gss_release_name(&minor_status, &client_name);
        if (kerberosToken) {
            /* Allocated by parseNegTokenInit, but no matching free function exists.. */
            if (!spnego_flag)
                safe_free(kerberosToken);
        }
        if (spnego_flag) {
            /* Allocated by makeNegTokenTarg, but no matching free function exists.. */
            safe_free(spnegoToken);
        }
        safe_free(token);
        safe_free(user);
        continue;
    }
}
#else
#include <cstdlib>
#ifndef MAX_AUTHTOKEN_LEN
#define MAX_AUTHTOKEN_LEN   65535
#endif
int
main(int argc, char *const argv[])
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char buf[MAX_AUTHTOKEN_LEN];
    while (1) {
        if (fgets(buf, sizeof(buf) - 1, stdin) == NULL) {
            fprintf(stdout, "BH input error\n");
            exit(0);
        }
        fprintf(stdout, "BH Kerberos authentication not supported\n");
    }
}
#endif /* HAVE_GSSAPI */

