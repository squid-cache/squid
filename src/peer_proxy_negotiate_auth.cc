/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: 11    Hypertext Transfer Protocol (HTTP)
 */

#include "squid.h"

#if HAVE_KRB5 && HAVE_GSSAPI
#if USE_APPLE_KRB5
#define KERBEROS_APPLE_DEPRECATED(x)
#define GSSKRB_APPLE_DEPRECATED(x)
#endif

#include "base64.h"
#include "Debug.h"
#include "peer_proxy_negotiate_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_PROFILE_H
#include <profile.h>
#endif              /* HAVE_PROFILE_H */
#if HAVE_KRB5_H
#if HAVE_BROKEN_SOLARIS_KRB5_H
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif
#include <krb5.h>
#elif HAVE_ET_COM_ERR_H
#include <et/com_err.h>
#endif                          /* HAVE_COM_ERR_H */
#if HAVE_COM_ERR_H
#include <com_err.h>
#endif              /* HAVE_COM_ERR_H */

#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif              /* HAVE_GSSAPI_H */
#if !USE_HEIMDAL_KRB5
#if HAVE_GSSAPI_GSSAPI_EXT_H
#include <gssapi/gssapi_ext.h>
#endif              /* HAVE_GSSAPI_GSSAPI_EXT_H */
#if HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif              /* HAVE_GSSAPI_GSSAPI_KRB5_H */
#if HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif              /* HAVE_GSSAPI_GSSAPI_GENERIC_H */
#endif              /* !USE_HEIMDAL_KRB5 */

#ifndef gss_nt_service_name
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#endif

#if !HAVE_ERROR_MESSAGE && HAVE_KRB5_GET_ERROR_MESSAGE
#define error_message(code) krb5_get_error_message(kparam.context,code)
#elif !HAVE_ERROR_MESSAGE && HAVE_KRB5_GET_ERR_TEXT
#define error_message(code) krb5_get_err_text(kparam.context,code)
#elif !HAVE_ERROR_MESSAGE
static char err_code[17];
const char *KRB5_CALLCONV
error_message(long code) {
    snprintf(err_code,16,"%ld",code);
    return err_code;
}
#endif

#ifndef gss_mech_spnego
static gss_OID_desc _gss_mech_spnego =
{ 6, (void *) "\x2b\x06\x01\x05\x05\x02" };
gss_OID gss_mech_spnego = &_gss_mech_spnego;
#endif

#if USE_IBM_KERBEROS
#include <ibm_svc/krb5_svc.h>
const char *KRB5_CALLCONV error_message(long code) {
    char *msg = NULL;
    krb5_svc_get_msg(code, &msg);
    return msg;
}
#endif

/*
 * Kerberos context and cache structure
 * Caches authentication details to reduce
 * number of authentication requests to kdc
 */
static struct kstruct {
    krb5_context context;
    krb5_ccache cc;
} kparam = {
    NULL, NULL
};

/*
 * krb5_create_cache creates a Kerberos file credential cache or a memory
 * credential cache if supported. The initial key for the principal
 * principal_name is extracted from the keytab keytab_filename.
 *
 * If keytab_filename is NULL the default will be used.
 * If principal_name is NULL the first working entry of the keytab will be used.
 */
int krb5_create_cache(char *keytab_filename, char *principal_name);

/*
 * krb5_cleanup clears used Keberos memory
 */
void krb5_cleanup(void);

/*
 * check_gss_err checks for gssapi error codes, extracts the error message
 * and prints it.
 */
int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
                  const char *function);

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status,
                  const char *function) {
    if (GSS_ERROR(major_status)) {
        OM_uint32 maj_stat, min_stat;
        OM_uint32 msg_ctx = 0;
        gss_buffer_desc status_string;
        char buf[1024];
        size_t len;

        len = 0;
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert major status code (GSS-API error) to text */
            maj_stat = gss_display_status(&min_stat, major_status,
                                          GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                if (sizeof(buf) > len + status_string.length + 1) {
                    memcpy(buf + len, status_string.value,
                           status_string.length);
                    len += status_string.length;
                }
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        if (sizeof(buf) > len + 2) {
            strcpy(buf + len, ". ");
            len += 2;
        }
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert minor status code (underlying routine error) to text */
            maj_stat = gss_display_status(&min_stat, minor_status,
                                          GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                if (sizeof(buf) > len + status_string.length) {
                    memcpy(buf + len, status_string.value,
                           status_string.length);
                    len += status_string.length;
                }
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        debugs(11, 5, HERE << function << "failed: " << buf);
        return (1);
    }
    return (0);
}

void krb5_cleanup() {
    debugs(11, 5, HERE << "Cleanup kerberos context");
    if (kparam.context) {
        if (kparam.cc)
            krb5_cc_destroy(kparam.context, kparam.cc);
        kparam.cc = NULL;
        krb5_free_context(kparam.context);
        kparam.context = NULL;
    }
}

int krb5_create_cache(char *kf, char *pn) {

#define KT_PATH_MAX 256
#define MAX_RENEW_TIME "365d"
#define DEFAULT_SKEW (krb5_deltat) 600

    static char *keytab_filename = NULL, *principal_name = NULL;
    static krb5_keytab keytab = 0;
    static krb5_keytab_entry entry;
    static krb5_kt_cursor cursor;
    static krb5_creds *creds = NULL;
#if USE_HEIMDAL_KRB5 && !HAVE_KRB5_GET_RENEWED_CREDS
    static krb5_creds creds2;
#endif
    static krb5_principal principal = NULL;
    static krb5_deltat skew;

#if HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
    krb5_get_init_creds_opt *options;
#else
    krb5_get_init_creds_opt options;
#endif
    krb5_error_code code = 0;
    krb5_deltat rlife;
#if HAVE_PROFILE_H && HAVE_KRB5_GET_PROFILE && HAVE_PROFILE_GET_INTEGER && HAVE_PROFILE_RELEASE
    profile_t profile;
#endif
#if USE_HEIMDAL_KRB5 && !HAVE_KRB5_GET_RENEWED_CREDS
    krb5_kdc_flags flags;
#if HAVE_KRB5_PRINCIPAL_GET_REALM
    const char *client_realm;
#else
    krb5_realm client_realm;
#endif
#endif
    char *mem_cache;

restart:
    /*
     * Check if credentials need to be renewed
     */
    if (creds &&
            (creds->times.endtime - time(0) > skew) &&
            (creds->times.renew_till - time(0) > 2 * skew)) {
        if (creds->times.endtime - time(0) < 2 * skew) {
#if HAVE_KRB5_GET_RENEWED_CREDS
            /* renew ticket */
            code =
                krb5_get_renewed_creds(kparam.context, creds, principal,
                                       kparam.cc, NULL);
#else
            /* renew ticket */
            flags.i = 0;
            flags.b.renewable = flags.b.renew = 1;

            code =
                krb5_cc_get_principal(kparam.context, kparam.cc,
                                      &creds2.client);
            if (code) {
                debugs(11, 5,
                       HERE <<
                       "Error while getting principal from credential cache : "
                       << error_message(code));
                return (1);
            }
#if HAVE_KRB5_PRINCIPAL_GET_REALM
            client_realm = krb5_principal_get_realm(kparam.context, principal);
#else
            client_realm = krb5_princ_realm(kparam.context, creds2.client);
#endif
            code =
                krb5_make_principal(kparam.context, &creds2.server,
                                    (krb5_const_realm)&client_realm, KRB5_TGS_NAME,
                                    (krb5_const_realm)&client_realm, NULL);
            if (code) {
                debugs(11, 5,
                       HERE << "Error while getting krbtgt principal : " <<
                       error_message(code));
                return (1);
            }
            code =
                krb5_get_kdc_cred(kparam.context, kparam.cc, flags, NULL,
                                  NULL, &creds2, &creds);
            krb5_free_creds(kparam.context, &creds2);
#endif
            if (code) {
                if (code == KRB5KRB_AP_ERR_TKT_EXPIRED) {
                    krb5_free_creds(kparam.context, creds);
                    creds = NULL;
                    /* this can happen because of clock skew */
                    goto restart;
                }
                debugs(11, 5,
                       HERE << "Error while get credentials : " <<
                       error_message(code));
                return (1);
            }
        }
    } else {
        /* reinit */
        if (!kparam.context) {
            code = krb5_init_context(&kparam.context);
            if (code) {
                debugs(11, 5,
                       HERE << "Error while initialising Kerberos library : "
                       << error_message(code));
                return (1);
            }
        }
#if HAVE_PROFILE_H && HAVE_KRB5_GET_PROFILE && HAVE_PROFILE_GET_INTEGER && HAVE_PROFILE_RELEASE
        code = krb5_get_profile(kparam.context, &profile);
        if (code) {
            if (profile)
                profile_release(profile);
            debugs(11, 5,
                   HERE << "Error while getting profile : " <<
                   error_message(code));
            return (1);
        }
        code =
            profile_get_integer(profile, "libdefaults", "clockskew", 0,
                                5 * 60, &skew);
        if (profile)
            profile_release(profile);
        if (code) {
            debugs(11, 5,
                   HERE << "Error while getting clockskew : " <<
                   error_message(code));
            return (1);
        }
#elif USE_HEIMDAL_KRB5 && HAVE_KRB5_GET_MAX_TIME_SKEW
        skew = krb5_get_max_time_skew(kparam.context);
#elif USE_HEIMDAL_KRB5 && HAVE_MAX_SKEW_IN_KRB5_CONTEXT
        skew = kparam.context->max_skew;
#else
        skew = DEFAULT_SKEW;
#endif

        if (!kf) {
            char buf[KT_PATH_MAX], *p;

            krb5_kt_default_name(kparam.context, buf, KT_PATH_MAX);
            p = strchr(buf, ':');
            if (p)
                ++p;
            xfree(keytab_filename);
            keytab_filename = xstrdup(p ? p : buf);
        } else {
            keytab_filename = xstrdup(kf);
        }

        code = krb5_kt_resolve(kparam.context, keytab_filename, &keytab);
        if (code) {
            debugs(11, 5,
                   HERE << "Error while resolving keytab filename " <<
                   keytab_filename << " : " << error_message(code));
            return (1);
        }

        if (!pn) {
            code = krb5_kt_start_seq_get(kparam.context, keytab, &cursor);
            if (code) {
                debugs(11, 5,
                       HERE << "Error while starting keytab scan : " <<
                       error_message(code));
                return (1);
            }
            code =
                krb5_kt_next_entry(kparam.context, keytab, &entry, &cursor);
            krb5_copy_principal(kparam.context, entry.principal,
                                &principal);
            if (code && code != KRB5_KT_END) {
                debugs(11, 5,
                       HERE << "Error while scanning keytab : " <<
                       error_message(code));
                return (1);
            }

            code = krb5_kt_end_seq_get(kparam.context, keytab, &cursor);
            if (code) {
                debugs(11, 5,
                       HERE << "Error while ending keytab scan : " <<
                       error_message(code));
                return (1);
            }
#if USE_HEIMDAL_KRB5 || ( HAVE_KRB5_KT_FREE_ENTRY && HAVE_DECL_KRB5_KT_FREE_ENTRY)
            code = krb5_kt_free_entry(kparam.context, &entry);
#else
            code = krb5_free_keytab_entry_contents(kparam.context, &entry);
#endif
            if (code) {
                debugs(11, 5,
                       HERE << "Error while freeing keytab entry : " <<
                       error_message(code));
                return (1);
            }

        } else {
            principal_name = xstrdup(pn);
        }

        if (!principal) {
            code =
                krb5_parse_name(kparam.context, principal_name, &principal);
            if (code) {
                debugs(11, 5,
                       HERE << "Error while parsing principal name " <<
                       principal_name << " : " << error_message(code));
                return (1);
            }
        }

        creds = (krb5_creds *) xmalloc(sizeof(*creds));
        memset(creds, 0, sizeof(*creds));
#if HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
        krb5_get_init_creds_opt_alloc(kparam.context, &options);
#else
        krb5_get_init_creds_opt_init(&options);
#endif
        code = krb5_string_to_deltat((char *) MAX_RENEW_TIME, &rlife);
        if (code != 0 || rlife == 0) {
            debugs(11, 5,
                   HERE << "Error bad lifetime value " << MAX_RENEW_TIME <<
                   " : " << error_message(code));
            return (1);
        }
#if HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
        krb5_get_init_creds_opt_set_renew_life(options, rlife);
        code =
            krb5_get_init_creds_keytab(kparam.context, creds, principal,
                                       keytab, 0, NULL, options);
#if HAVE_KRB5_GET_INIT_CREDS_FREE_CONTEXT
        krb5_get_init_creds_opt_free(kparam.context, options);
#else
        krb5_get_init_creds_opt_free(options);
#endif
#else
        krb5_get_init_creds_opt_set_renew_life(&options, rlife);
        code =
            krb5_get_init_creds_keytab(kparam.context, creds, principal,
                                       keytab, 0, NULL, &options);
#endif
        if (code) {
            debugs(11, 5,
                   HERE <<
                   "Error while initializing credentials from keytab : " <<
                   error_message(code));
            return (1);
        }
#if !HAVE_KRB5_MEMORY_CACHE
        mem_cache =
            (char *) xmalloc(strlen("FILE:/tmp/peer_proxy_negotiate_auth_")
                             + 16);
        if (!mem_cache) {
            debugs(11, 5, "Error while allocating memory");
            return(1);
        }
        snprintf(mem_cache,
                 strlen("FILE:/tmp/peer_proxy_negotiate_auth_") + 16,
                 "FILE:/tmp/peer_proxy_negotiate_auth_%d", (int) getpid());
#else
        mem_cache =
            (char *) xmalloc(strlen("MEMORY:peer_proxy_negotiate_auth_") +
                             16);
        if (!mem_cache) {
            debugs(11, 5, "Error while allocating memory");
            return(1);
        }
        snprintf(mem_cache,
                 strlen("MEMORY:peer_proxy_negotiate_auth_") + 16,
                 "MEMORY:peer_proxy_negotiate_auth_%d", (int) getpid());
#endif

        setenv("KRB5CCNAME", mem_cache, 1);
        code = krb5_cc_resolve(kparam.context, mem_cache, &kparam.cc);
        xfree(mem_cache);
        if (code) {
            debugs(11, 5,
                   HERE << "Error while resolving memory credential cache : "
                   << error_message(code));
            return (1);
        }
        code = krb5_cc_initialize(kparam.context, kparam.cc, principal);
        if (code) {
            debugs(11, 5,
                   HERE <<
                   "Error while initializing memory credential cache : " <<
                   error_message(code));
            return (1);
        }
        code = krb5_cc_store_cred(kparam.context, kparam.cc, creds);
        if (code) {
            debugs(11, 5,
                   HERE << "Error while storing credentials : " <<
                   error_message(code));
            return (1);
        }

        if (!creds->times.starttime)
            creds->times.starttime = creds->times.authtime;
    }
    return (0);
}

/*
 * peer_proxy_negotiate_auth gets a GSSAPI token for principal_name
 * and base64 encodes it.
 */
char *peer_proxy_negotiate_auth(char *principal_name, char *proxy, int flags) {
    int rc = 0;
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
        debugs(11, 5, HERE << "Error : No proxy server name");
        return NULL;
    }

    if (!(flags & PEER_PROXY_NEGOTIATE_NOKEYTAB)) {
        if (principal_name)
            debugs(11, 5,
                   HERE << "Creating credential cache for " << principal_name);
        else
            debugs(11, 5, HERE << "Creating credential cache");
        rc = krb5_create_cache(NULL, principal_name);
        if (rc) {
            debugs(11, 5, HERE << "Error : Failed to create Kerberos cache");
            krb5_cleanup();
            return NULL;
        }
    }

    service.value = (void *) xmalloc(strlen("HTTP") + strlen(proxy) + 2);
    snprintf((char *) service.value, strlen("HTTP") + strlen(proxy) + 2,
             "%s@%s", "HTTP", proxy);
    service.length = strlen((char *) service.value);

    debugs(11, 5, HERE << "Import gss name");
    major_status = gss_import_name(&minor_status, &service,
                                   gss_nt_service_name, &server_name);

    if (check_gss_err(major_status, minor_status, "gss_import_name()"))
        goto cleanup;

    debugs(11, 5, HERE << "Initialize gss security context");
    major_status = gss_init_sec_context(&minor_status,
                                        GSS_C_NO_CREDENTIAL,
                                        &gss_context,
                                        server_name,
                                        gss_mech_spnego,
                                        0,
                                        0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token, NULL, &output_token, NULL, NULL);

    if (check_gss_err(major_status, minor_status, "gss_init_sec_context()"))
        goto cleanup;

    debugs(11, 5, HERE << "Got token with length " << output_token.length);
    if (output_token.length) {
        static uint8_t b64buf[8192]; // XXX: 8KB only because base64_encode_bin() used to.
        struct base64_encode_ctx ctx;
        base64_encode_init(&ctx);
        size_t blen = base64_encode_update(&ctx, b64buf, output_token.length, reinterpret_cast<const uint8_t*>(output_token.value));
        blen += base64_encode_final(&ctx, b64buf+blen);
        b64buf[blen] = '\0';

        token = reinterpret_cast<char*>(b64buf);
    }

cleanup:
    gss_delete_sec_context(&minor_status, &gss_context, NULL);
    gss_release_buffer(&minor_status, &service);
    gss_release_buffer(&minor_status, &input_token);
    gss_release_buffer(&minor_status, &output_token);
    gss_release_name(&minor_status, &server_name);

    return token;
}

#ifdef __cplusplus
}
#endif
#endif /* HAVE_KRB5 && HAVE_GSSAPI */

