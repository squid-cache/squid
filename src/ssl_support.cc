
/*
 * $Id: ssl_support.cc,v 1.13 2003/04/17 15:25:44 hno Exp $
 *
 * AUTHOR: Benno Rice
 * DEBUG: section 83    SSL accelerator support
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "fde.h"

extern int commUnsetNonBlocking(int fd);
extern int commSetNonBlocking(int fd);

void clientNegotiateSSL(int fd, void *data);
void clientReadSSLRequest(int fd, void *data);

static RSA *
ssl_temp_rsa_cb(SSL * ssl, int anInt, int keylen)
{
    static RSA *rsa = NULL;

    if (rsa == NULL)
        rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);

    return rsa;
}

static int
ssl_verify_cb(int ok, X509_STORE_CTX * ctx)
{
    char buffer[256];
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SSL_CTX *sslctx = SSL_get_SSL_CTX(ssl);
    const char *server = (const char *)SSL_get_ex_data(ssl, ssl_ex_index_server);
    void *dont_verify_domain = SSL_CTX_get_ex_data(sslctx, ssl_ctx_ex_index_dont_verify_domain);
    X509 *peer_cert = ctx->cert;

    X509_NAME_oneline(X509_get_subject_name(peer_cert), buffer,
                      sizeof(buffer));

    if (ok) {
        debug(83, 5) ("SSL Certificate signature OK: %s\n", buffer);

        if (server) {
            int i;
            int found = 0;
            char cn[1024];
            X509_NAME *name = X509_get_subject_name(peer_cert);
            debug(83, 3) ("Verifying server domain %s to certificate dn %s\n",
                          server, buffer);

            for (i = X509_NAME_get_index_by_NID(name, NID_commonName, -1); i >= 0; i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) {
                ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

                if (data->length > (int)sizeof(cn) - 1)
                    continue;

                memcpy(cn, data->data, data->length);

                cn[data->length] = '\0';

                debug(83, 4) ("Verifying server domain %s to certificate cn %s\n",
                              server, cn);

                if (matchDomainName(server, cn[0] == '*' ? cn + 1 : cn) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                debug(83, 2) ("ERROR: Certificate %s does not match domainname %s\n", buffer, server);
                ok = 0;
            }
        }
    } else {
        switch (ctx->error) {

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            debug(83, 5) ("SSL Certficate error: CA not known: %s\n", buffer);
            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
            debug(83, 5) ("SSL Certficate not yet valid: %s\n", buffer);
            break;

        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            debug(83, 5) ("SSL Certificate has illegal \'not before\' field: %s\n", buffer);
            break;

        case X509_V_ERR_CERT_HAS_EXPIRED:
            debug(83, 5) ("SSL Certificate expired: %s\n", buffer);
            break;

        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            debug(83, 5) ("SSL Certificate has invalid \'not after\' field: %s\n", buffer);
            break;

        default:
            debug(83, 1) ("SSL unknown certificate error %d in %s\n",
                          ctx->error, buffer);
            break;
        }
    }

if (!dont_verify_domain && server) {}

    return ok;
}

static struct ssl_option
{
    const char *name;
    long value;
}

ssl_options[] = {

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
                    {
                        "MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG
                    },
#endif
#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
                    {
                        "NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG
                    },
#endif
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
                    {
                        "NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
                    },
#endif
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
                    {
                        "SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
                    },
#endif
#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
                    {
                        "MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
                    },
#endif
#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
                    {
                        "MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING
                    },
#endif
#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
                    {
                        "SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG
                    },
#endif
#ifdef SSL_OP_TLS_D5_BUG
                    {
                        "TLS_D5_BUG", SSL_OP_TLS_D5_BUG
                    },
#endif
#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
                    {
                        "TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG
                    },
#endif
#ifdef SSL_OP_TLS_ROLLBACK_BUG
                    {
                        "TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG
                    },
#endif
#ifdef SSL_OP_ALL
                    {
                        "ALL", SSL_OP_ALL
                    },
#endif
#ifdef SSL_OP_SINGLE_DH_USE
                    {
                        "SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE
                    },
#endif
#ifdef SSL_OP_EPHEMERAL_RSA
                    {
                        "EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA
                    },
#endif
#ifdef SSL_OP_PKCS1_CHECK_1
                    {
                        "PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1
                    },
#endif
#ifdef SSL_OP_PKCS1_CHECK_2
                    {
                        "PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2
                    },
#endif
#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
                    {
                        "NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG
                    },
#endif
#ifdef SSL_OP_NON_EXPORT_FIRST
                    {
                        "NON_EXPORT_FIRST", SSL_OP_NON_EXPORT_FIRST
                    },
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
                    {
                        "CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE
                    },
#endif
#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
                    {
                        "NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
                    },
#endif
#ifdef SSL_OP_NO_SSLv2
                    {
                        "NO_SSLv2", SSL_OP_NO_SSLv2
                    },
#endif
#ifdef SSL_OP_NO_SSLv3
                    {
                        "NO_SSLv3", SSL_OP_NO_SSLv3
                    },
#endif
#ifdef SSL_OP_NO_TLSv1
                    {
                        "NO_TLSv1", SSL_OP_NO_TLSv1
                    },
#endif
                    {
                        "", 0
                    },
                    {
                        NULL, 0
                    }
                };

static long
ssl_parse_options(const char *options)
{
    long op = SSL_OP_ALL;
    char *tmp;
    char *option;

    if (!options)
        goto no_options;

    tmp = xstrdup(options);

    option = strtok(tmp, ":,");

    while (option) {

        struct ssl_option *opt = NULL, *opttmp;
        long value = 0;
        enum {
            MODE_ADD, MODE_REMOVE
        } mode;

        switch (*option) {

        case '!':

        case '-':
            mode = MODE_REMOVE;
            option++;
            break;

        case '+':
            mode = MODE_ADD;
            option++;
            break;

        default:
            mode = MODE_ADD;
            break;
        }

        for (opttmp = ssl_options; opttmp->name; opttmp++) {
            if (strcmp(opttmp->name, option) == 0) {
                opt = opttmp;
                break;
            }
        }

        if (opt)
            value = opt->value;
        else if (strncmp(option, "0x", 2) == 0) {
            /* Special case.. hex specification */
            value = strtol(option + 2, NULL, 16);
        } else {
            fatalf("Unknown SSL option '%s'", option);
            value = 0;		/* Keep GCC happy */
        }

        switch (mode) {

        case MODE_ADD:
            op |= value;
            break;

        case MODE_REMOVE:
            op &= ~value;
            break;
        }

        option = strtok(NULL, ":,");
    }

    safe_free(tmp);

no_options:
    return op;
}

#define SSL_FLAG_NO_DEFAULT_CA		(1<<0)
#define SSL_FLAG_DELAYED_AUTH		(1<<1)
#define SSL_FLAG_DONT_VERIFY_PEER	(1<<2)
#define SSL_FLAG_DONT_VERIFY_DOMAIN	(1<<3)

static long
ssl_parse_flags(const char *flags)
{
    long fl = 0;
    char *tmp;
    char *flag;

    if (!flags)
        return 0;

    tmp = xstrdup(flags);

    flag = strtok(tmp, ":,");

    while (flag) {
        if (strcmp(flag, "NO_DEFAULT_CA") == 0)
            fl |= SSL_FLAG_NO_DEFAULT_CA;
        else if (strcmp(flag, "DELAYED_AUTH") == 0)
            fl |= SSL_FLAG_DELAYED_AUTH;
        else if (strcmp(flag, "DONT_VERIFY_PEER") == 0)
            fl |= SSL_FLAG_DONT_VERIFY_PEER;
        else if (strcmp(flag, "DONT_VERIFY_DOMAIN") == 0)
            fl |= SSL_FLAG_DONT_VERIFY_DOMAIN;
        else
            fatalf("Unknown ssl flag '%s'", flag);

        flag = strtok(NULL, ":,");
    }

    safe_free(tmp);
    return fl;
}


static void
ssl_initialize(void)
{
    static int ssl_initialized = 0;

    if (!ssl_initialized) {
        ssl_initialized = 1;
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
#ifdef HAVE_OPENSSL_ENGINE_H

        if (Config.SSL.ssl_engine) {
            ENGINE *e;

            if (!(e = ENGINE_by_id(Config.SSL.ssl_engine))) {
                fatalf("Unable to find SSL engine '%s'\n", Config.SSL.ssl_engine);
            }

            if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                int ssl_error = ERR_get_error();
                fatalf("Failed to initialise SSL engine: %s\n",
                       ERR_error_string(ssl_error, NULL));
            }
        }

#else
        if (Config.SSL.ssl_engine) {
            fatalf("Your OpenSSL has no SSL engine support\n");
        }

#endif

    }

    ssl_ex_index_server = SSL_get_ex_new_index(0, (void *) "server", NULL, NULL, NULL);
    ssl_ctx_ex_index_dont_verify_domain = SSL_CTX_get_ex_new_index(0, (void *) "dont_verify_domain", NULL, NULL, NULL);

}

SSL_CTX *
sslCreateServerContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *clientCA, const char *CAfile, const char *CApath, const char *dhfile)
{
    int ssl_error;
    SSL_METHOD *method;
    SSL_CTX *sslContext;
    long fl = ssl_parse_flags(flags);

    ssl_initialize();

    if (!keyfile)
        keyfile = certfile;

    if (!certfile)
        certfile = keyfile;

    if (!CAfile)
        CAfile = clientCA;

    debug(83, 1) ("Initialising SSL.\n");

    switch (version) {

    case 2:
        debug(83, 5) ("Using SSLv2.\n");
        method = SSLv2_server_method();
        break;

    case 3:
        debug(83, 5) ("Using SSLv3.\n");
        method = SSLv3_server_method();
        break;

    case 4:
        debug(83, 5) ("Using TLSv1.\n");
        method = TLSv1_server_method();
        break;

    case 1:

    default:
        debug(83, 5) ("Using SSLv2/SSLv3.\n");
        method = SSLv23_server_method();
        break;
    }

    sslContext = SSL_CTX_new(method);

    if (sslContext == NULL) {
        ssl_error = ERR_get_error();
        fatalf("Failed to allocate SSL context: %s\n",
               ERR_error_string(ssl_error, NULL));
    }

    SSL_CTX_set_options(sslContext, ssl_parse_options(options));

    if (cipher) {
        debug(83, 5) ("Using chiper suite %s.\n", cipher);

        if (!SSL_CTX_set_cipher_list(sslContext, cipher)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to set SSL cipher suite '%s': %s\n",
                   cipher, ERR_error_string(ssl_error, NULL));
        }
    }

    debug(83, 1) ("Using certificate in %s\n", certfile);

    if (!SSL_CTX_use_certificate_chain_file(sslContext, certfile)) {
        ssl_error = ERR_get_error();
        debug(83, 0) ("Failed to acquire SSL certificate '%s': %s\n",
                      certfile, ERR_error_string(ssl_error, NULL));
        goto error;
    }

    debug(83, 1) ("Using private key in %s\n", keyfile);

    if (!SSL_CTX_use_PrivateKey_file(sslContext, keyfile, SSL_FILETYPE_PEM)) {
        ssl_error = ERR_get_error();
        debug(83, 0) ("Failed to acquire SSL private key '%s': %s\n",
                      keyfile, ERR_error_string(ssl_error, NULL));
        goto error;
    }

    debug(83, 5) ("Comparing private and public SSL keys.\n");

    if (!SSL_CTX_check_private_key(sslContext)) {
        ssl_error = ERR_get_error();
        debug(83, 0) ("SSL private key '%s' does not match public key '%s': %s\n",
                      certfile, keyfile, ERR_error_string(ssl_error, NULL));
        goto error;
    }

    debug(83, 9) ("Setting RSA key generation callback.\n");
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);

    debug(83, 9) ("Setting CA certificate locations.\n");

    if ((!SSL_CTX_load_verify_locations(sslContext, CAfile, CApath))) {
        ssl_error = ERR_get_error();
        debug(83, 1) ("Error error setting CA certificate locations: %s\n",
                      ERR_error_string(ssl_error, NULL));
        debug(83, 1) ("continuing anyway...\n");
    }

    if (!(fl & SSL_FLAG_NO_DEFAULT_CA) &&
            !SSL_CTX_set_default_verify_paths(sslContext)) {
        ssl_error = ERR_get_error();
        debug(83, 1) ("Error error setting default CA certificate location: %s\n",
                      ERR_error_string(ssl_error, NULL));
        debug(83, 1) ("continuing anyway...\n");
    }

    if (clientCA) {
        debug(83, 9) ("Set client certifying authority list.\n");
        SSL_CTX_set_client_CA_list(sslContext, SSL_load_client_CA_file(clientCA));

        if (fl & SSL_FLAG_DELAYED_AUTH) {
            debug(83, 9) ("Not requesting client certificates until acl processing requires one\n");
            SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
        } else {
            debug(83, 9) ("Requiring client certificates.\n");
            SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_cb);
        }
    } else {
        debug(83, 9) ("Not requiring any client certificates\n");
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
    }

    if (dhfile) {
        FILE *in = fopen(dhfile, "r");
        DH *dh = NULL;
        int codes;

        if (in) {
            dh = PEM_read_DHparams(in, NULL, NULL, NULL);
            fclose(in);
        }

        if (!dh)
            debug(83, 1) ("WARNING: Failed to read DH parameters '%s'\n", dhfile);
        else if (dh && DH_check(dh, &codes) == 0) {
            if (codes) {
                debug(83, 1) ("WARNING: Failed to verify DH parameters '%s' (%x)\n", dhfile, codes);
                DH_free(dh);
                dh = NULL;
            }
        }

        if (dh)
            SSL_CTX_set_tmp_dh(sslContext, dh);
    }

    if (fl & SSL_FLAG_DONT_VERIFY_DOMAIN)
        SSL_CTX_set_ex_data(sslContext, ssl_ctx_ex_index_dont_verify_domain, (void *) -1);

    return sslContext;

error:
    SSL_CTX_free(sslContext);

    return NULL;
}

SSL_CTX *
sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath)
{
    int ssl_error;
    SSL_METHOD *method;
    SSL_CTX *sslContext;
    long fl = ssl_parse_flags(flags);

    ssl_initialize();

    if (!keyfile)
        keyfile = certfile;

    if (!certfile)
        certfile = keyfile;

    debug(83, 1) ("Initialising SSL.\n");

    switch (version) {

    case 2:
        debug(83, 5) ("Using SSLv2.\n");
        method = SSLv2_client_method();
        break;

    case 3:
        debug(83, 5) ("Using SSLv3.\n");
        method = SSLv3_client_method();
        break;

    case 4:
        debug(83, 5) ("Using TLSv1.\n");
        method = TLSv1_client_method();
        break;

    case 1:

    default:
        debug(83, 5) ("Using SSLv2/SSLv3.\n");
        method = SSLv23_client_method();
        break;
    }

    sslContext = SSL_CTX_new(method);

    if (sslContext == NULL) {
        ssl_error = ERR_get_error();
        fatalf("Failed to allocate SSL context: %s\n",
               ERR_error_string(ssl_error, NULL));
    }

    SSL_CTX_set_options(sslContext, ssl_parse_options(options));

    if (cipher) {
        debug(83, 5) ("Using chiper suite %s.\n", cipher);

        if (!SSL_CTX_set_cipher_list(sslContext, cipher)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to set SSL cipher suite '%s': %s\n",
                   cipher, ERR_error_string(ssl_error, NULL));
        }
    }

    if (certfile) {
        debug(83, 1) ("Using certificate in %s\n", certfile);

        if (!SSL_CTX_use_certificate_chain_file(sslContext, certfile)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to acquire SSL certificate '%s': %s\n",
                   certfile, ERR_error_string(ssl_error, NULL));
        }

        debug(83, 1) ("Using private key in %s\n", keyfile);

        if (!SSL_CTX_use_PrivateKey_file(sslContext, keyfile, SSL_FILETYPE_PEM)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to acquire SSL private key '%s': %s\n",
                   keyfile, ERR_error_string(ssl_error, NULL));
        }

        debug(83, 5) ("Comparing private and public SSL keys.\n");

        if (!SSL_CTX_check_private_key(sslContext)) {
            ssl_error = ERR_get_error();
            fatalf("SSL private key '%s' does not match public key '%s': %s\n",
                   certfile, keyfile, ERR_error_string(ssl_error, NULL));
        }
    }

    debug(83, 9) ("Setting RSA key generation callback.\n");
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);

    if (fl & SSL_FLAG_DONT_VERIFY_PEER) {
        debug(83, 1) ("NOTICE: Peer certificates are not verified for validity!\n");
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
    } else {
        debug(83, 9) ("Setting certificate verification callback.\n");
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_cb);
    }

    debug(83, 9) ("Setting CA certificate locations.\n");

    if ((!SSL_CTX_load_verify_locations(sslContext, CAfile, CApath))) {
        ssl_error = ERR_get_error();
        debug(83, 1) ("Error error setting CA certificate locations: %s\n",
                      ERR_error_string(ssl_error, NULL));
        debug(83, 1) ("continuing anyway...\n");
    }

    if (!(fl & SSL_FLAG_NO_DEFAULT_CA) &&
            !SSL_CTX_set_default_verify_paths(sslContext)) {
        ssl_error = ERR_get_error();
        debug(83, 1) ("Error error setting default CA certificate location: %s\n",
                      ERR_error_string(ssl_error, NULL));
        debug(83, 1) ("continuing anyway...\n");
    }

    return sslContext;
}

int
ssl_read_method(int fd, char *buf, int len)
{
    int i;

    i = SSL_read(fd_table[fd].ssl, buf, len);

    if (i > 0 && SSL_pending(fd_table[fd].ssl) > 0) {
        debug(83, 2) ("SSL fd %d is pending\n", fd);
        fd_table[fd].flags.read_pending = 1;
    } else
        fd_table[fd].flags.read_pending = 0;

    return i;
}

int
ssl_write_method(int fd, const char *buf, int len)
{
    return (SSL_write(fd_table[fd].ssl, buf, len));
}

void
ssl_shutdown_method(int fd)
{
    SSL *ssl = fd_table[fd].ssl;

    if (!fd_table[fd].ssl_shutdown) {
        fd_table[fd].ssl_shutdown = 1;

        if (Config.SSL.unclean_shutdown)
            SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        else
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    }

    SSL_shutdown(ssl);
}

static const char *
ssl_get_attribute(X509_NAME * name, const char *attribute_name)
{
    static char buffer[1024];
    int nid;

    buffer[0] = '\0';

    if (strcmp(attribute_name, "DN") == 0) {
        X509_NAME_oneline(name, buffer, sizeof(buffer));
        goto done;
    }

    nid = OBJ_txt2nid((char *) attribute_name);

    if (nid == 0) {
        debug(83, 1) ("WARNING: Unknown SSL attribute name '%s'\n", attribute_name);
        return NULL;
    }

    X509_NAME_get_text_by_NID(name, nid, buffer, sizeof(buffer));

done:
    return *buffer ? buffer : NULL;
}

const char *
sslGetUserAttribute(SSL * ssl, const char *attribute_name)
{
    X509 *cert;
    X509_NAME *name;

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    name = X509_get_issuer_name(cert);

    return ssl_get_attribute(name, attribute_name);
}

const char *
sslGetCAAttribute(SSL * ssl, const char *attribute_name)
{
    X509 *cert;
    X509_NAME *name;

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    name = X509_get_subject_name(cert);

    return ssl_get_attribute(name, attribute_name);
}

#if 0
char *
sslGetUserEmail(SSL * ssl)
{
    X509 *cert;
    X509_NAME *name;

    static char email[128];

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    name = X509_get_subject_name(cert);

    if (X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, email, sizeof(email)) > 0)
        return email;
    else
        return NULL;
}

#endif

const char *
sslGetUserEmail(SSL * ssl)
{
    return sslGetUserAttribute(ssl, "Email");
}
