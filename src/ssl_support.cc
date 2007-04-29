
/*
 * $Id: ssl_support.cc,v 1.35 2007/04/28 22:26:37 hno Exp $
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

static int
ssl_ask_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    FILE *in;
    int len = 0;
    char cmdline[1024];

    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\"", Config.Program.ssl_password, (const char *)userdata);
    in = popen(cmdline, "r");

    if (fgets(buf, size, in))

        len = strlen(buf);

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))

        len--;

    buf[len] = '\0';

    pclose(in);

    return len;
}

static void
ssl_ask_password(SSL_CTX * context, const char * prompt)
{
    if (Config.Program.ssl_password) {
        SSL_CTX_set_default_passwd_cb(context, ssl_ask_password_cb);
        SSL_CTX_set_default_passwd_cb_userdata(context, (void *)prompt);
    }
}

static RSA *
ssl_temp_rsa_cb(SSL * ssl, int anInt, int keylen)
{
    static RSA *rsa_512 = NULL;
    static RSA *rsa_1024 = NULL;
    RSA *rsa = NULL;
    int newkey = 0;

    switch (keylen) {

    case 512:

        if (!rsa_512) {
            rsa_512 = RSA_generate_key(512, RSA_F4, NULL, NULL);
            newkey = 1;
        }

        rsa = rsa_512;
        break;

    case 1024:

        if (!rsa_1024) {
            rsa_1024 = RSA_generate_key(1024, RSA_F4, NULL, NULL);
            newkey = 1;
        }

        rsa = rsa_1024;
        break;

    default:
        debugs(83, 1, "ssl_temp_rsa_cb: Unexpected key length " << keylen);
        return NULL;
    }

    if (rsa == NULL) {
        debugs(83, 1, "ssl_temp_rsa_cb: Failed to generate key " << keylen);
        return NULL;
    }

    if (newkey) {
        if (do_debug(83, 5))
            PEM_write_RSAPrivateKey(debug_log, rsa, NULL, NULL, 0, NULL, NULL);

        debugs(83, 1, "Generated ephemeral RSA key of length " << keylen);
    }

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
        debugs(83, 5, "SSL Certificate signature OK: " << buffer);

        if (server) {
            int i;
            int found = 0;
            char cn[1024];
            X509_NAME *name = X509_get_subject_name(peer_cert);
            debugs(83, 3, "Verifying server domain " << server << " to certificate dn " << buffer);

            for (i = X509_NAME_get_index_by_NID(name, NID_commonName, -1); i >= 0; i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) {
                ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

                if (data->length > (int)sizeof(cn) - 1)
                    continue;

                memcpy(cn, data->data, data->length);

                cn[data->length] = '\0';

                debugs(83, 4, "Verifying server domain " << server << " to certificate cn " << cn);

                if (matchDomainName(server, cn[0] == '*' ? cn + 1 : cn) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                debugs(83, 2, "ERROR: Certificate " << buffer << " does not match domainname " << server);
                ok = 0;
            }
        }
    } else {
        switch (ctx->error) {

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            debugs(83, 5, "SSL Certficate error: CA not known: " << buffer);
            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
            debugs(83, 5, "SSL Certficate not yet valid: " << buffer);
            break;

        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            debugs(83, 5, "SSL Certificate has illegal \'not before\' field: " <<
                   buffer);
            
            break;

        case X509_V_ERR_CERT_HAS_EXPIRED:
            debugs(83, 5, "SSL Certificate expired: " << buffer);
            break;

        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            debugs(83, 5, "SSL Certificate has invalid \'not after\' field: " << buffer);
            break;

        default:
            debugs(83, 1, "SSL unknown certificate error " << ctx->error << " in " << buffer);
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
#define SSL_FLAG_NO_SESSION_REUSE	(1<<4)
#define SSL_FLAG_VERIFY_CRL		(1<<5)
#define SSL_FLAG_VERIFY_CRL_ALL		(1<<6)

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
        else if (strcmp(flag, "NO_SESSION_REUSE") == 0)
            fl |= SSL_FLAG_NO_SESSION_REUSE;

#ifdef X509_V_FLAG_CRL_CHECK

        else if (strcmp(flag, "VERIFY_CRL") == 0)
            fl |= SSL_FLAG_VERIFY_CRL;
        else if (strcmp(flag, "VERIFY_CRL_ALL") == 0)
            fl |= SSL_FLAG_VERIFY_CRL_ALL;

#endif

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

static int
ssl_load_crl(SSL_CTX *sslContext, const char *CRLfile)
{
    X509_STORE *st = SSL_CTX_get_cert_store(sslContext);
    X509_CRL *crl;
    BIO *in = BIO_new_file(CRLfile, "r");
    int count = 0;

    if (!in) {
        debugs(83, 2, "WARNING: Failed to open CRL file '" << CRLfile << "'");
        return 0;
    }

    while ((crl = PEM_read_bio_X509_CRL(in,NULL,NULL,NULL))) {
        if (!X509_STORE_add_crl(st, crl))
            debugs(83, 2, "WARNING: Failed to add CRL from file '" << CRLfile << "'");
        else
            count++;

        X509_CRL_free(crl);
    }

    BIO_free(in);
    return count;
}

SSL_CTX *
sslCreateServerContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *clientCA, const char *CAfile, const char *CApath, const char *CRLfile, const char *dhfile, const char *context)
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

    switch (version) {

    case 2:
        debugs(83, 5, "Using SSLv2.");
        method = SSLv2_server_method();
        break;

    case 3:
        debugs(83, 5, "Using SSLv3.");
        method = SSLv3_server_method();
        break;

    case 4:
        debugs(83, 5, "Using TLSv1.");
        method = TLSv1_server_method();
        break;

    case 1:

    default:
        debugs(83, 5, "Using SSLv2/SSLv3.");
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

    if (context && *context) {
        SSL_CTX_set_session_id_context(sslContext, (const unsigned char *)context, strlen(context));
    }

    if (fl & SSL_FLAG_NO_SESSION_REUSE) {
        SSL_CTX_set_session_cache_mode(sslContext, SSL_SESS_CACHE_OFF);
    }

    if (Config.SSL.unclean_shutdown) {
        debugs(83, 5, "Enabling quiet SSL shutdowns (RFC violation).");

        SSL_CTX_set_quiet_shutdown(sslContext, 1);
    }

    if (cipher) {
        debugs(83, 5, "Using chiper suite " << cipher << ".");

        if (!SSL_CTX_set_cipher_list(sslContext, cipher)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to set SSL cipher suite '%s': %s\n",
                   cipher, ERR_error_string(ssl_error, NULL));
        }
    }

    debugs(83, 1, "Using certificate in " << certfile);

    if (!SSL_CTX_use_certificate_chain_file(sslContext, certfile)) {
        ssl_error = ERR_get_error();
        debugs(83, 0, "Failed to acquire SSL certificate '" << certfile << "': " << ERR_error_string(ssl_error, NULL)  );
        goto error;
    }

    debugs(83, 1, "Using private key in " << keyfile);
    ssl_ask_password(sslContext, keyfile);

    if (!SSL_CTX_use_PrivateKey_file(sslContext, keyfile, SSL_FILETYPE_PEM)) {
        ssl_error = ERR_get_error();
        debugs(83, 0, "Failed to acquire SSL private key '" << keyfile << "': " << ERR_error_string(ssl_error, NULL)  );
        goto error;
    }

    debugs(83, 5, "Comparing private and public SSL keys.");

    if (!SSL_CTX_check_private_key(sslContext)) {
        ssl_error = ERR_get_error();
        debugs(83, 0, "SSL private key '" << 
               certfile << "' does not match public key '" <<
               keyfile << "': " << ERR_error_string(ssl_error, NULL)  );
        goto error;
    }

    debugs(83, 9, "Setting RSA key generation callback.");
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);

    debugs(83, 9, "Setting CA certificate locations.");

    if ((CAfile || CApath) && !SSL_CTX_load_verify_locations(sslContext, CAfile, CApath)) {
        ssl_error = ERR_get_error();
        debugs(83, 1, "Error setting CA certificate locations: " << ERR_error_string(ssl_error, NULL)  );
        debugs(83, 1, "continuing anyway..." );
    }

    if (!(fl & SSL_FLAG_NO_DEFAULT_CA) &&
            !SSL_CTX_set_default_verify_paths(sslContext)) {
        ssl_error = ERR_get_error();
        debugs(83, 1, "Error setting default CA certificate location: " << ERR_error_string(ssl_error, NULL)  );
        debugs(83, 1, "continuing anyway..." );
    }

    if (clientCA) {
        STACK_OF(X509_NAME) *cert_names;
        debugs(83, 9, "Set client certifying authority list.");
        cert_names = SSL_load_client_CA_file(clientCA);

        if (cert_names == NULL) {
            debugs(83, 1, "Error loading the client CA certificates from '" << clientCA << "\': " << ERR_error_string(ERR_get_error(),NULL)  ); 
            goto error;
        }

        ERR_clear_error();
        SSL_CTX_set_client_CA_list(sslContext, cert_names);

        if (fl & SSL_FLAG_DELAYED_AUTH) {
            debugs(83, 9, "Not requesting client certificates until acl processing requires one");
            SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
        } else {
            debugs(83, 9, "Requiring client certificates.");
            SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_cb);
        }

        if (CRLfile) {
            ssl_load_crl(sslContext, CRLfile);
            fl |= SSL_FLAG_VERIFY_CRL;
        }

#ifdef X509_V_FLAG_CRL_CHECK
        if (fl & SSL_FLAG_VERIFY_CRL_ALL)
            X509_STORE_set_flags(SSL_CTX_get_cert_store(sslContext), X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
        else if (fl & SSL_FLAG_VERIFY_CRL)
            X509_STORE_set_flags(SSL_CTX_get_cert_store(sslContext), X509_V_FLAG_CRL_CHECK);

#endif

    } else {
        debugs(83, 9, "Not requiring any client certificates");
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
            debugs(83, 1, "WARNING: Failed to read DH parameters '" << dhfile << "'");
        else if (dh && DH_check(dh, &codes) == 0) {
            if (codes) {
                debugs(83, 1, "WARNING: Failed to verify DH parameters '" << dhfile  << "' (" << std::hex << codes  << ")");
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
sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile)
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

    switch (version) {

    case 2:
        debugs(83, 5, "Using SSLv2.");
        method = SSLv2_client_method();
        break;

    case 3:
        debugs(83, 5, "Using SSLv3.");
        method = SSLv3_client_method();
        break;

    case 4:
        debugs(83, 5, "Using TLSv1.");
        method = TLSv1_client_method();
        break;

    case 1:

    default:
        debugs(83, 5, "Using SSLv2/SSLv3.");
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
        debugs(83, 5, "Using chiper suite " << cipher << ".");

        if (!SSL_CTX_set_cipher_list(sslContext, cipher)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to set SSL cipher suite '%s': %s\n",
                   cipher, ERR_error_string(ssl_error, NULL));
        }
    }

    if (certfile) {
        debugs(83, 1, "Using certificate in " << certfile);

        if (!SSL_CTX_use_certificate_chain_file(sslContext, certfile)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to acquire SSL certificate '%s': %s\n",
                   certfile, ERR_error_string(ssl_error, NULL));
        }

        debugs(83, 1, "Using private key in " << keyfile);
        ssl_ask_password(sslContext, keyfile);

        if (!SSL_CTX_use_PrivateKey_file(sslContext, keyfile, SSL_FILETYPE_PEM)) {
            ssl_error = ERR_get_error();
            fatalf("Failed to acquire SSL private key '%s': %s\n",
                   keyfile, ERR_error_string(ssl_error, NULL));
        }

        debugs(83, 5, "Comparing private and public SSL keys.");

        if (!SSL_CTX_check_private_key(sslContext)) {
            ssl_error = ERR_get_error();
            fatalf("SSL private key '%s' does not match public key '%s': %s\n",
                   certfile, keyfile, ERR_error_string(ssl_error, NULL));
        }
    }

    debugs(83, 9, "Setting RSA key generation callback.");
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);

    if (fl & SSL_FLAG_DONT_VERIFY_PEER) {
        debugs(83, 1, "NOTICE: Peer certificates are not verified for validity!");
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
    } else {
        debugs(83, 9, "Setting certificate verification callback.");
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_cb);
    }

    debugs(83, 9, "Setting CA certificate locations.");

    if ((CAfile || CApath) && !SSL_CTX_load_verify_locations(sslContext, CAfile, CApath)) {
        ssl_error = ERR_get_error();
        debugs(83, 1, "Error setting CA certificate locations: " << ERR_error_string(ssl_error, NULL));
        debugs(83, 1, "continuing anyway..." );
    }

    if (CRLfile) {
        ssl_load_crl(sslContext, CRLfile);
        fl |= SSL_FLAG_VERIFY_CRL;
    }

#ifdef X509_V_FLAG_CRL_CHECK
    if (fl & SSL_FLAG_VERIFY_CRL_ALL)
        X509_STORE_set_flags(SSL_CTX_get_cert_store(sslContext), X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
    else if (fl & SSL_FLAG_VERIFY_CRL)
        X509_STORE_set_flags(SSL_CTX_get_cert_store(sslContext), X509_V_FLAG_CRL_CHECK);

#endif

    if (!(fl & SSL_FLAG_NO_DEFAULT_CA) &&
            !SSL_CTX_set_default_verify_paths(sslContext)) {
        ssl_error = ERR_get_error();
        debugs(83, 1, "Error setting default CA certificate location: " << ERR_error_string(ssl_error, NULL)  );
        debugs(83, 1, "continuing anyway...");
    }

    return sslContext;
}

int
ssl_read_method(int fd, char *buf, int len)
{
    SSL *ssl = fd_table[fd].ssl;
    int i;

#if DONT_DO_THIS

    if (!SSL_is_init_finished(ssl)) {
        errno = ENOTCONN;
        return -1;
    }

#endif

    i = SSL_read(ssl, buf, len);

    if (i > 0 && SSL_pending(ssl) > 0) {
        debugs(83, 2, "SSL FD " << fd << " is pending");
        fd_table[fd].flags.read_pending = 1;
    } else
        fd_table[fd].flags.read_pending = 0;

    return i;
}

int
ssl_write_method(int fd, const char *buf, int len)
{
    SSL *ssl = fd_table[fd].ssl;
    int i;

    if (!SSL_is_init_finished(ssl)) {
        errno = ENOTCONN;
        return -1;
    }

    i = SSL_write(ssl, buf, len);

    return i;
}

void
ssl_shutdown_method(int fd)
{
    SSL *ssl = fd_table[fd].ssl;

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
        debugs(83, 1, "WARNING: Unknown SSL attribute name '" << attribute_name << "'");
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
    const char *ret;

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    name = X509_get_subject_name(cert);

    ret = ssl_get_attribute(name, attribute_name);

    X509_free(cert);

    return ret;
}

const char *
sslGetCAAttribute(SSL * ssl, const char *attribute_name)
{
    X509 *cert;
    X509_NAME *name;
    const char *ret;

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    name = X509_get_issuer_name(cert);

    ret = ssl_get_attribute(name, attribute_name);

    X509_free(cert);

    return ret;
}

const char *
sslGetUserEmail(SSL * ssl)
{
    return sslGetUserAttribute(ssl, "emailAddress");
}

const char *
sslGetUserCertificatePEM(SSL *ssl)
{
    X509 *cert;
    BIO *mem;
    static char *str = NULL;
    char *ptr;
    long len;

    safe_free(str);

    if (!ssl)
        return NULL;

    cert = SSL_get_peer_certificate(ssl);

    if (!cert)
        return NULL;

    mem = BIO_new(BIO_s_mem());

    PEM_write_bio_X509(mem, cert);


    len = BIO_get_mem_data(mem, &ptr);

    str = (char *)xmalloc(len + 1);

    memcpy(str, ptr, len);

    str[len] = '\0';

    X509_free(cert);

    BIO_free(mem);

    return str;
}

const char *
sslGetUserCertificateChainPEM(SSL *ssl)
{
    STACK_OF(X509) *chain;
    BIO *mem;
    static char *str = NULL;
    char *ptr;
    long len;
    int i;

    safe_free(str);

    if (!ssl)
        return NULL;

    chain = SSL_get_peer_cert_chain(ssl);

    if (!chain)
        return sslGetUserCertificatePEM(ssl);

    mem = BIO_new(BIO_s_mem());

    for (i = 0; i < sk_X509_num(chain); i++) {
        X509 *cert = sk_X509_value(chain, i);
        PEM_write_bio_X509(mem, cert);
    }

    len = BIO_get_mem_data(mem, &ptr);

    str = (char *)xmalloc(len + 1);
    memcpy(str, ptr, len);
    str[len] = '\0';

    BIO_free(mem);

    return str;
}
