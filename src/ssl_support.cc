
/*
 * $Id: ssl_support.cc,v 1.4 2001/10/19 22:34:49 hno Exp $
 *
 * AUTHOR: Benno Rice
 * DEBUG: section 81     SSL accelerator support
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

extern int commUnsetNonBlocking(int fd);
extern int commSetNonBlocking(int fd);

void clientNegotiateSSL(int fd, void *data);
void clientReadSSLRequest(int fd, void *data);

static RSA *
ssl_temp_rsa_cb(SSL * ssl, int export, int keylen)
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

    X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buffer,
	sizeof(buffer));
    if (ok)
	debug(81, 5) ("SSL Certificate OK: %s\n", buffer);
    else {
	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    debug(81, 5) ("SSL Certficate error: CA not known: %s\n", buffer);
	    break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	    debug(81, 5) ("SSL Certficate not yet valid: %s\n", buffer);
	    break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	    debug(81, 5) ("SSL Certificate has illegal \'not before\' field: %s\n", buffer);
	    break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	    debug(81, 5) ("SSL Certificate expired: %s\n", buffer);
	    break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	    debug(81, 5) ("SSL Certificate has invalid \'not after\' field: %s\n", buffer);
	    break;
	default:
	    debug(81, 5) ("SSL unknown certificate error %d in %s\n",
		ctx->error, buffer);
	    break;
	}
    }
    return ok;
}

static struct ssl_option {
    const char *name;
    long value;
} ssl_options[] = {

    {
	"MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG
    },
    {
	"NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG
    },
    {
	"NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    },
    {
	"SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    },
    {
	"MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    },
    {
	"MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING
    },
    {
	"SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    },
    {
	"TLS_D5_BUG", SSL_OP_TLS_D5_BUG
    },
    {
	"TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG
    },
    {
	"TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG
    },
    {
	"SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE
    },
    {
	"EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA
    },
    {
	"PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1
    },
    {
	"PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2
    },
    {
	"NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG
    },
    {
	"NON_EXPORT_FIRST", SSL_OP_NON_EXPORT_FIRST
    },
    {
	"NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
    },
    {
	"ALL", SSL_OP_ALL
    },
    {
	"NO_SSLv2", SSL_OP_NO_SSLv2
    },
    {
	"NO_SSLv3", SSL_OP_NO_SSLv3
    },
    {
	"NO_TLSv1", SSL_OP_NO_TLSv1
    },
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

SSL_CTX *
sslCreateContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options)
{
    int ssl_error;
    SSL_METHOD *method;
    SSL_CTX *sslContext;
    static int ssl_initialized = 0;
    if (!ssl_initialized) {
	ssl_initialized = 1;
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
    }
    if (!keyfile)
	keyfile = certfile;
    if (!certfile)
	certfile = keyfile;

    debug(81, 1) ("Initialising SSL.\n");
    switch (version) {
    case 2:
	debug(81, 5) ("Using SSLv2.\n");
	method = SSLv2_server_method();
	break;
    case 3:
	debug(81, 5) ("Using SSLv3.\n");
	method = SSLv3_server_method();
	break;
    case 4:
	debug(81, 5) ("Using TLSv1.\n");
	method = TLSv1_server_method();
	break;
    case 1:
    default:
	debug(81, 5) ("Using SSLv2/SSLv3.\n");
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
	debug(81, 5) ("Using chiper suite %s.\n", cipher);
	if (!SSL_CTX_set_cipher_list(sslContext, cipher)) {
	    ssl_error = ERR_get_error();
	    fatalf("Failed to set SSL cipher suite: %s\n",
		ERR_error_string(ssl_error, NULL));
	}
    }
    debug(81, 1) ("Using certificate in %s\n", certfile);
    if (!SSL_CTX_use_certificate_file(sslContext, certfile, SSL_FILETYPE_PEM)) {
	ssl_error = ERR_get_error();
	fatalf("Failed to acquire SSL certificate: %s\n",
	    ERR_error_string(ssl_error, NULL));
    }
    debug(81, 1) ("Using private key in %s\n", keyfile);
    if (!SSL_CTX_use_PrivateKey_file(sslContext, keyfile, SSL_FILETYPE_PEM)) {
	ssl_error = ERR_get_error();
	fatalf("Failed to acquire SSL private key: %s\n",
	    ERR_error_string(ssl_error, NULL));
    }
    debug(81, 5) ("Comparing private and public SSL keys.\n");
    if (!SSL_CTX_check_private_key(sslContext))
	fatal("SSL private key does not match public key: %s\n");

    debug(81, 9) ("Setting RSA key generation callback.\n");
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);

    debug(81, 9) ("Setting certificate verification callback.\n");
    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, ssl_verify_cb);

    debug(81, 9) ("Setting default CA certificate location.\n");
    if (!SSL_CTX_set_default_verify_paths(sslContext)) {
	ssl_error = ERR_get_error();
	debug(81, 1) ("Error error setting default CA certificate location: %s\n",
	    ERR_error_string(ssl_error, NULL));
	debug(81, 1) ("continuing anyway...\n");
    }
    debug(81, 9) ("Set client certifying authority list.\n");
    SSL_CTX_set_client_CA_list(sslContext, SSL_load_client_CA_file(certfile));
    return sslContext;
}

int
ssl_read_method(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    int i;

    i = SSL_read(fd_table[fd].ssl, buf, len);

    if (i > 0 && SSL_pending(fd_table[fd].ssl) > 0) {
	debug(81, 2) ("SSL fd %d is pending\n", fd);
	fd_table[fd].flags.read_pending = 1;
    } else
	fd_table[fd].flags.read_pending = 0;

    return i;
}

int
ssl_write_method(fd, buf, len)
     int fd;
     const char *buf;
     int len;
{
    return (SSL_write(fd_table[fd].ssl, buf, len));
}

void
ssl_shutdown_method(fd)
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
