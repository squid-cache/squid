/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL accelerator support */

#include "squid.h"
#include "ssl/support.h"

/* support.cc says this is needed */
#if USE_OPENSSL

#include "comm.h"
#include "fde.h"
#include "globals.h"
#include "ip/Address.h"
#include "ssl/bio.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#undef DO_SSLV23

#if _SQUID_WINDOWS_
extern int socket_read_method(int, char *, int);
extern int socket_write_method(int, const char *, int);
#endif

/* BIO callbacks */
static int squid_bio_write(BIO *h, const char *buf, int num);
static int squid_bio_read(BIO *h, char *buf, int size);
static int squid_bio_puts(BIO *h, const char *str);
//static int squid_bio_gets(BIO *h, char *str, int size);
static long squid_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int squid_bio_create(BIO *h);
static int squid_bio_destroy(BIO *data);
/* SSL callbacks */
static void squid_ssl_info(const SSL *ssl, int where, int ret);

/// Initialization structure for the BIO table with
/// Squid-specific methods and BIO method wrappers.
static BIO_METHOD SquidMethods = {
    BIO_TYPE_SOCKET,
    "squid",
    squid_bio_write,
    squid_bio_read,
    squid_bio_puts,
    NULL, // squid_bio_gets not supported
    squid_bio_ctrl,
    squid_bio_create,
    squid_bio_destroy,
    NULL // squid_callback_ctrl not supported
};

BIO *
Ssl::Bio::Create(const int fd, Ssl::Bio::Type type)
{
    if (BIO *bio = BIO_new(&SquidMethods)) {
        BIO_int_ctrl(bio, BIO_C_SET_FD, type, fd);
        return bio;
    }
    return NULL;
}

void
Ssl::Bio::Link(SSL *ssl, BIO *bio)
{
    SSL_set_bio(ssl, bio, bio); // cannot fail
    SSL_set_info_callback(ssl, &squid_ssl_info); // does not provide diagnostic
}

Ssl::Bio::Bio(const int anFd): fd_(anFd)
{
    debugs(83, 7, "Bio constructed, this=" << this << " FD " << fd_);
}

Ssl::Bio::~Bio()
{
    debugs(83, 7, "Bio destructing, this=" << this << " FD " << fd_);
}

int Ssl::Bio::write(const char *buf, int size, BIO *table)
{
    errno = 0;
#if _SQUID_WINDOWS_
    const int result = socket_write_method(fd_, buf, size);
#else
    const int result = default_write_method(fd_, buf, size);
#endif
    const int xerrno = errno;
    debugs(83, 5, "FD " << fd_ << " wrote " << result << " <= " << size);

    BIO_clear_retry_flags(table);
    if (result < 0) {
        const bool ignoreError = ignoreErrno(xerrno) != 0;
        debugs(83, 5, "error: " << xerrno << " ignored: " << ignoreError);
        if (ignoreError)
            BIO_set_retry_write(table);
    }

    return result;
}

int
Ssl::Bio::read(char *buf, int size, BIO *table)
{
    errno = 0;
#if _SQUID_WINDOWS_
    const int result = socket_read_method(fd_, buf, size);
#else
    const int result = default_read_method(fd_, buf, size);
#endif
    const int xerrno = errno;
    debugs(83, 5, "FD " << fd_ << " read " << result << " <= " << size);

    BIO_clear_retry_flags(table);
    if (result < 0) {
        const bool ignoreError = ignoreErrno(xerrno) != 0;
        debugs(83, 5, "error: " << xerrno << " ignored: " << ignoreError);
        if (ignoreError)
            BIO_set_retry_read(table);
    }

    return result;
}

/// Called whenever the SSL connection state changes, an alert appears, or an
/// error occurs. See SSL_set_info_callback().
void
Ssl::Bio::stateChanged(const SSL *ssl, int where, int ret)
{
    // Here we can use (where & STATE) to check the current state.
    // Many STATE values are possible, including: SSL_CB_CONNECT_LOOP,
    // SSL_CB_ACCEPT_LOOP, SSL_CB_HANDSHAKE_START, and SSL_CB_HANDSHAKE_DONE.
    // For example:
    // if (where & SSL_CB_HANDSHAKE_START)
    //    debugs(83, 9, "Trying to establish the SSL connection");
    // else if (where & SSL_CB_HANDSHAKE_DONE)
    //    debugs(83, 9, "SSL connection established");

    debugs(83, 7, "FD " << fd_ << " now: 0x" << std::hex << where << std::dec << ' ' <<
           SSL_state_string(ssl) << " (" << SSL_state_string_long(ssl) << ")");
}

bool
Ssl::ClientBio::isClientHello(int state)
{
    return (state == SSL2_ST_GET_CLIENT_HELLO_A ||
            state == SSL3_ST_SR_CLNT_HELLO_A ||
            state == SSL23_ST_SR_CLNT_HELLO_A ||
            state == SSL23_ST_SR_CLNT_HELLO_B ||
            state == SSL3_ST_SR_CLNT_HELLO_B ||
            state == SSL3_ST_SR_CLNT_HELLO_C
           );
}

void
Ssl::ClientBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
}

int
Ssl::ClientBio::write(const char *buf, int size, BIO *table)
{
    if (holdWrite_) {
        BIO_set_retry_write(table);
        return 0;
    }

    return Ssl::Bio::write(buf, size, table);
}

const char *objToString(unsigned char const *bytes, int len)
{
    static std::string buf;
    buf.clear();
    for (int i = 0; i < len; i++ ) {
        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%.2x", bytes[i]);
        buf.append(tmp);
    }
    return buf.c_str();
}

int
Ssl::ClientBio::read(char *buf, int size, BIO *table)
{
    if (helloState < atHelloReceived) {

        if (rbuf.isNull())
            rbuf.init(1024, 16384);

        size = rbuf.spaceSize() > size ? size : rbuf.spaceSize();

        if (!size)
            return 0;

        int bytes = Ssl::Bio::read(buf, size, table);
        if (bytes <= 0)
            return bytes;
        rbuf.append(buf, bytes);
        debugs(83, 7, "rbuf size: " << rbuf.contentSize());
    }

    if (helloState == atHelloNone) {

        const unsigned char *head = (const unsigned char *)rbuf.content();
        const char *s = objToString(head, rbuf.contentSize());
        debugs(83, 7, "SSL Header: " << s);
        if (rbuf.contentSize() < 5) {
            BIO_set_retry_read(table);
            return 0;
        }

        if (head[0] == 0x16) {
            debugs(83, 7, "SSL version 3 handshake message");
            helloSize = (head[3] << 8) + head[4];
            debugs(83, 7, "SSL Header Size: " << helloSize);
            helloSize +=5;
#if defined(DO_SSLV23)
        } else if ((head[0] & 0x80) && head[2] == 0x01 && head[3] == 0x03) {
            debugs(83, 7, "SSL version 2 handshake message with v3 support");
            helloSize = head[1];
            helloSize +=5;
#endif
        } else {
            debugs(83, 7, "Not an SSL acceptable handshake message (SSLv2 message?)");
            wrongProtocol = true;
            return -1;
        }

        helloState = atHelloStarted; //Next state
    }

    if (helloState == atHelloStarted) {
        const unsigned char *head = (const unsigned char *)rbuf.content();
        const char *s = objToString(head, rbuf.contentSize());
        debugs(83, 7, "SSL Header: " << s);

        if (helloSize > rbuf.contentSize()) {
            BIO_set_retry_read(table);
            return -1;
        }
        features.get((const unsigned char *)rbuf.content());
        helloState = atHelloReceived;
    }

    if (holdRead_) {
        debugs(83, 7, "Hold flag is set, retry latter. (Hold " << size << "bytes)");
        BIO_set_retry_read(table);
        return -1;
    }

    if (helloState == atHelloReceived) {
        if (rbuf.hasContent()) {
            int bytes = (size <= rbuf.contentSize() ? size : rbuf.contentSize());
            memcpy(buf, rbuf.content(), bytes);
            rbuf.consume(bytes);
            return bytes;
        } else
            return Ssl::Bio::read(buf, size, table);
    }

    return -1;
}

void
Ssl::ServerBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
}

void
Ssl::ServerBio::setClientFeatures(const Ssl::Bio::sslFeatures &features)
{
    clientFeatures.sslVersion = features.sslVersion;
    clientFeatures.compressMethod = features.compressMethod;
    clientFeatures.serverName = features.serverName;
    clientFeatures.clientRequestedCiphers = features.clientRequestedCiphers;
    clientFeatures.unknownCiphers = features.unknownCiphers;
    memcpy(clientFeatures.client_random, features.client_random, SSL3_RANDOM_SIZE);
    clientFeatures.helloMessage.clear();
    clientFeatures.helloMessage.append(features.helloMessage.rawContent(), features.helloMessage.length());
    clientFeatures.doHeartBeats = features.doHeartBeats;
    clientFeatures.extensions = features.extensions;
    featuresSet = true;
};

int
Ssl::ServerBio::read(char *buf, int size, BIO *table)
{
    int bytes = Ssl::Bio::read(buf, size, table);

    if (bytes > 0 && record_) {
        if (rbuf.isNull())
            rbuf.init(1024, 16384);
        rbuf.append(buf, bytes);
        debugs(83, 5, "Record is enabled store " << bytes << " bytes");
    }
    debugs(83, 5, "Read " << bytes << " from " << size << " bytes");
    return bytes;
}

// This function makes the required checks to examine if the client hello
// message is compatible with the features provided by OpenSSL toolkit.
// If the features are compatible and can be supported it tries to rewrite SSL
// structure members, to replace the hello message created by openSSL, with the
// web client SSL hello message.
// This is mostly possible in the cases where the web client uses openSSL
// library similar with this one used by squid.
static bool
adjustSSL(SSL *ssl, Ssl::Bio::sslFeatures &features)
{
#if SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK
    if (!ssl->s3) {
        debugs(83, 5, "No SSLv3 data found!");
        return false;
    }

    // If the client supports compression but our context does not support
    // we can not adjust.
    if (features.compressMethod && ssl->ctx->comp_methods == NULL) {
        debugs(83, 5, "Client Hello Data supports compression, but we do not!");
        return false;
    }

    // Check ciphers list
    size_t token = 0;
    size_t end = 0;
    while (token != std::string::npos) {
        end = features.clientRequestedCiphers.find(':',token);
        std::string cipher;
        cipher.assign(features.clientRequestedCiphers, token, end - token);
        token = (end != std::string::npos ? end + 1 : std::string::npos);
        bool found = false;
        STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(ssl);
        for (int i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);
            const char *cname = SSL_CIPHER_get_name(c);
            if (cipher.compare(cname)) {
                found = true;
                break;
            }
        }
        if (!found) {
            debugs(83, 5, "Client Hello Data supports cipher '"<< cipher <<"' but we do not support it!");
            return false;
        }
    }

#if !defined(SSL_TLSEXT_HB_ENABLED)
    if (features.doHeartBeats) {
        debugs(83, 5, "Client Hello Data supports HeartBeats but we do not support!");
        return false;
    }
#endif

    for (std::list<int>::iterator it = features.extensions.begin(); it != features.extensions.end(); ++it) {
        static int supportedExtensions[] = {
#if defined(TLSEXT_TYPE_server_name)
            TLSEXT_TYPE_server_name,
#endif
#if defined(TLSEXT_TYPE_opaque_prf_input)
            TLSEXT_TYPE_opaque_prf_input,
#endif
#if defined(TLSEXT_TYPE_heartbeat)
            TLSEXT_TYPE_heartbeat,
#endif
#if defined(TLSEXT_TYPE_renegotiate)
            TLSEXT_TYPE_renegotiate,
#endif
#if defined(TLSEXT_TYPE_ec_point_formats)
            TLSEXT_TYPE_ec_point_formats,
#endif
#if defined(TLSEXT_TYPE_elliptic_curves)
            TLSEXT_TYPE_elliptic_curves,
#endif
#if defined(TLSEXT_TYPE_session_ticket)
            TLSEXT_TYPE_session_ticket,
#endif
#if defined(TLSEXT_TYPE_status_request)
            TLSEXT_TYPE_status_request,
#endif
#if defined(TLSEXT_TYPE_use_srtp)
            TLSEXT_TYPE_use_srtp,
#endif
#if 0 //Allow 13172 Firefox supported extension for testing purposes
            13172,
#endif
            -1
        };
        bool found = false;
        for (int i = 0; supportedExtensions[i] != -1; i++) {
            if (*it == supportedExtensions[i]) {
                found = true;
                break;
            }
        }
        if (!found) {
            debugs(83, 5, "Extension " << *it <<  " does not supported!");
            return false;
        }
    }

    SSL3_BUFFER *wb=&(ssl->s3->wbuf);
    if (wb->len < (size_t)features.helloMessage.length())
        return false;

    debugs(83, 5, "OpenSSL SSL struct will be adjusted to mimic client hello data!");

    //Adjust ssl structure data.
    // We need to fix the random in SSL struct:
    memcpy(ssl->s3->client_random, features.client_random, SSL3_RANDOM_SIZE);
    memcpy(wb->buf, features.helloMessage.rawContent(), features.helloMessage.length());
    wb->left = features.helloMessage.length();

    size_t mainHelloSize = features.helloMessage.length() - 5;
    const char *mainHello = features.helloMessage.rawContent() + 5;
    assert((size_t)ssl->init_buf->max > mainHelloSize);
    memcpy(ssl->init_buf->data, mainHello, mainHelloSize);
    debugs(83, 5, "Hello Data init and adjustd sizes :" << ssl->init_num << " = "<< mainHelloSize);
    ssl->init_num = mainHelloSize;
    ssl->s3->wpend_ret = mainHelloSize;
    ssl->s3->wpend_tot = mainHelloSize;
    return true;
#else
    return false;
#endif
}

int
Ssl::ServerBio::write(const char *buf, int size, BIO *table)
{

    if (holdWrite_) {
        debugs(83, 7,  "Hold write, for SSL connection on " << fd_ << "will not write bytes of size " << size);
        BIO_set_retry_write(table);
        return -1;
    }

    if (!helloBuild && (bumpMode_ == Ssl::bumpPeek || bumpMode_ == Ssl::bumpStare)) {
        if (
            buf[1] >= 3  //it is an SSL Version3 message
            && buf[0] == 0x16 // and it is a Handshake/Hello message
        ) {

            //Hello message is the first message we write to server
            assert(helloMsg.isEmpty());

            SSL *ssl = fd_table[fd_].ssl;
            if (featuresSet && ssl) {
                if (bumpMode_ == Ssl::bumpPeek) {
                    if (adjustSSL(ssl, clientFeatures))
                        allowBump = true;
                    allowSplice = true;
                    helloMsg.append(clientFeatures.helloMessage);
                    debugs(83, 7,  "SSL HELLO message for FD " << fd_ << ": Random number is adjusted for peek mode");
                } else { /*Ssl::bumpStare*/
                    allowBump = true;
                    if (adjustSSL(ssl, clientFeatures)) {
                        allowSplice = true;
                        helloMsg.append(clientFeatures.helloMessage);
                        debugs(83, 7,  "SSL HELLO message for FD " << fd_ << ": Random number is adjusted for stare mode");
                    }
                }
            }
        }
        // If we do not build any hello message, copy the current
        if (helloMsg.isEmpty())
            helloMsg.append(buf, size);

        helloBuild = true;
        helloMsgSize = helloMsg.length();
        //allowBump = true;

        if (allowSplice) {
            // Do not write yet.....
            BIO_set_retry_write(table);
            return -1;
        }
    }

    if (!helloMsg.isEmpty()) {
        debugs(83, 7,  "buffered write for FD " << fd_);
        int ret = Ssl::Bio::write(helloMsg.rawContent(), helloMsg.length(), table);
        helloMsg.consume(ret);
        if (!helloMsg.isEmpty()) {
            // We need to retry sendind data.
            // Say to openSSL to retry sending hello message
            BIO_set_retry_write(table);
            return -1;
        }

        // Sending hello message complete. Do not send more data for now...
        holdWrite_ = true;

        // spoof openSSL that we write what it ask us to write
        return size;
    } else
        return Ssl::Bio::write(buf, size, table);
}

void
Ssl::ServerBio::flush(BIO *table)
{
    if (!helloMsg.isEmpty()) {
        int ret = Ssl::Bio::write(helloMsg.rawContent(), helloMsg.length(), table);
        helloMsg.consume(ret);
    }
}

/// initializes BIO table after allocation
static int
squid_bio_create(BIO *bi)
{
    bi->init = 0; // set when we store Bio object and socket fd (BIO_C_SET_FD)
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return 1;
}

/// cleans BIO table before deallocation
static int
squid_bio_destroy(BIO *table)
{
    delete static_cast<Ssl::Bio*>(table->ptr);
    table->ptr = NULL;
    return 1;
}

/// wrapper for Bio::write()
static int
squid_bio_write(BIO *table, const char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
    assert(bio);
    return bio->write(buf, size, table);
}

/// wrapper for Bio::read()
static int
squid_bio_read(BIO *table, char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
    assert(bio);
    return bio->read(buf, size, table);
}

/// implements puts() via write()
static int
squid_bio_puts(BIO *table, const char *str)
{
    assert(str);
    return squid_bio_write(table, str, strlen(str));
}

/// other BIO manipulations (those without dedicated callbacks in BIO table)
static long
squid_bio_ctrl(BIO *table, int cmd, long arg1, void *arg2)
{
    debugs(83, 5, table << ' ' << cmd << '(' << arg1 << ", " << arg2 << ')');

    switch (cmd) {
    case BIO_C_SET_FD: {
        assert(arg2);
        const int fd = *static_cast<int*>(arg2);
        Ssl::Bio *bio;
        if (arg1 == Ssl::Bio::BIO_TO_SERVER)
            bio = new Ssl::ServerBio(fd);
        else
            bio = new Ssl::ClientBio(fd);
        assert(!table->ptr);
        table->ptr = bio;
        table->init = 1;
        return 0;
    }

    case BIO_C_GET_FD:
        if (table->init) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
            assert(bio);
            if (arg2)
                *static_cast<int*>(arg2) = bio->fd();
            return bio->fd();
        }
        return -1;

    case BIO_CTRL_DUP:
        // Should implemented if the SSL_dup openSSL API function
        // used anywhere in squid.
        return 0;

    case BIO_CTRL_FLUSH:
        if (table->init) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
            assert(bio);
            bio->flush(table);
            return 1;
        }
        return 0;

    /*  we may also need to implement these:
        case BIO_CTRL_RESET:
        case BIO_C_FILE_SEEK:
        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
        case BIO_CTRL_GET_CLOSE:
        case BIO_CTRL_SET_CLOSE:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
    */
    default:
        return 0;

    }

    return 0; /* NOTREACHED */
}

/// wrapper for Bio::stateChanged()
static void
squid_ssl_info(const SSL *ssl, int where, int ret)
{
    if (BIO *table = SSL_get_rbio(ssl)) {
        if (Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr))
            bio->stateChanged(ssl, where, ret);
    }
}

Ssl::Bio::sslFeatures::sslFeatures(): sslVersion(-1), compressMethod(-1), unknownCiphers(false), doHeartBeats(true)
{
    memset(client_random, 0, SSL3_RANDOM_SIZE);
}

int Ssl::Bio::sslFeatures::toSquidSSLVersion() const
{
    if (sslVersion == SSL2_VERSION)
        return 2;
    else if (sslVersion == SSL3_VERSION)
        return 3;
    else if (sslVersion == TLS1_VERSION)
        return 4;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    else if (sslVersion == TLS1_1_VERSION)
        return 5;
    else if (sslVersion == TLS1_2_VERSION)
        return 6;
#endif
    else
        return 1;
}

bool
Ssl::Bio::sslFeatures::get(const SSL *ssl)
{
    sslVersion = SSL_version(ssl);
    debugs(83, 7, "SSL version: " << SSL_get_version(ssl) << " (" << sslVersion << ")");

#if defined(TLSEXT_NAMETYPE_host_name)
    if (const char *server = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
        serverName = server;
    debugs(83, 7, "SNI server name: " << serverName);
#endif

    if (ssl->session->compress_meth)
        compressMethod = ssl->session->compress_meth;
    else if (sslVersion >= 3) //if it is 3 or newer version then compression is disabled
        compressMethod = 0;
    debugs(83, 7, "SSL compression: " << compressMethod);

    STACK_OF(SSL_CIPHER) * ciphers = NULL;
    if (ssl->server)
        ciphers = ssl->session->ciphers;
    else
        ciphers = ssl->cipher_list;
    if (ciphers) {
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
            if (c != NULL) {
                if (!clientRequestedCiphers.empty())
                    clientRequestedCiphers.append(":");
                clientRequestedCiphers.append(c->name);
            }
        }
    }
    debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

    if (sslVersion >=3 && ssl->s3 && ssl->s3->client_random[0]) {
        memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
    }

#if 0 /* XXX: OpenSSL 0.9.8k lacks at least some of these tlsext_* fields */
    //The following extracted for logging purpuses:
    // TLSEXT_TYPE_ec_point_formats
    unsigned char *p;
    int len;
    if (ssl->server) {
        p = ssl->session->tlsext_ecpointformatlist;
        len = ssl->session->tlsext_ecpointformatlist_length;
    } else {
        p = ssl->tlsext_ecpointformatlist;
        len = ssl->tlsext_ecpointformatlist_length;
    }
    if (p) {
        ecPointFormatList = objToString(p, len);
        debugs(83, 7, "tlsExtension ecPointFormatList of length " << len << " :" << ecPointFormatList);
    }

    // TLSEXT_TYPE_elliptic_curves
    if (ssl->server) {
        p = ssl->session->tlsext_ellipticcurvelist;
        len = ssl->session->tlsext_ellipticcurvelist_length;
    } else {
        p = ssl->tlsext_ellipticcurvelist;
        len = ssl->tlsext_ellipticcurvelist_length;
    }
    if (p) {
        ellipticCurves = objToString(p, len);
        debugs(83, 7, "tlsExtension ellipticCurveList of length " <<  len <<" :" << ellipticCurves);
    }
    // TLSEXT_TYPE_opaque_prf_input
    p = NULL;
    if (ssl->server) {
        if (ssl->s3 &&  ssl->s3->client_opaque_prf_input) {
            p = (unsigned char *)ssl->s3->client_opaque_prf_input;
            len = ssl->s3->client_opaque_prf_input_len;
        }
    } else {
        p = (unsigned char *)ssl->tlsext_opaque_prf_input;
        len = ssl->tlsext_opaque_prf_input_len;
    }
    if (p) {
        debugs(83, 7, "tlsExtension client-opaque-prf-input of length " << len);
        opaquePrf = objToString(p, len);
    }
#endif
    return true;
}

bool
Ssl::Bio::sslFeatures::get(const unsigned char *hello)
{
    // The SSL handshake message should starts with a 0x16 byte
    if (hello[0] == 0x16) {
        return parseV3Hello(hello);
#if defined(DO_SSLV23)
    } else if ((hello[0] & 0x80) && hello[2] == 0x01 && hello[3] == 0x03) {
        return parseV23Hello(hello);
#endif
    }

    debugs(83, 7, "Not a known SSL handshake message");
    return false;
}

bool
Ssl::Bio::sslFeatures::parseV3Hello(const unsigned char *hello)
{
    debugs(83, 7, "Get fake features from v3 hello message.");
    // The SSL version exist in the 2nd and 3rd bytes
    sslVersion = (hello[1] << 8) | hello[2];
    debugs(83, 7, "Get fake features. Version :" << std::hex << std::setw(8) << std::setfill('0')<< sslVersion);

    // The following hello message size exist in 4th and 5th bytes
    int helloSize = (hello[3] << 8) | hello[4];
    helloSize += 5; //Include the 5 header bytes.
    helloMessage.clear();
    helloMessage.append((const char *)hello, helloSize);

    //For SSLv3 or TLSv1.* protocols we can get some more informations
    if (hello[1] == 0x3 && hello[5] == 0x1 /*HELLO A message*/) {
        // Get the correct version of the sub-hello message
        sslVersion = (hello[9] << 8) | hello[10];
        //Get Client Random number. It starts on the position 11 of hello message
        memcpy(client_random, hello + 11, SSL3_RANDOM_SIZE);
        debugs(83, 7, "Client random: " <<  objToString(client_random, SSL3_RANDOM_SIZE));

        // At the position 43 (11+SSL3_RANDOM_SIZE)
        int sessIDLen = (int)hello[43];
        debugs(83, 7, "Session ID Length: " <<  sessIDLen);

        //Ciphers list. It is stored after the Session ID.
        const unsigned char *ciphers = hello + 44 + sessIDLen;
        int ciphersLen = (ciphers[0] << 8) | ciphers[1];
        ciphers += 2;
        if (ciphersLen) {
            const SSL_METHOD *method = SSLv3_method();
            int cs = method->put_cipher_by_char(NULL, NULL);
            assert(cs > 0);
            for (int i = 0; i < ciphersLen; i += cs) {
                const SSL_CIPHER *c = method->get_cipher_by_char((ciphers + i));
                if (c != NULL) {
                    if (!clientRequestedCiphers.empty())
                        clientRequestedCiphers.append(":");
                    clientRequestedCiphers.append(c->name);
                } else
                    unknownCiphers = true;
            }
        }
        debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

        // Compression field: 1 bytes the number of compression methods and
        // 1 byte for each compression method
        const unsigned char *compression = ciphers + ciphersLen;
        if (compression[0] > 1)
            compressMethod = 1;
        else
            compressMethod = 0;
        debugs(83, 7, "SSL compression methods number: " << (int)compression[0]);

        const unsigned char *pToExtensions = compression + 1 + (int)compression[0];
        if (pToExtensions <  hello + helloSize) {
            int extensionsLen = (pToExtensions[0] << 8) | pToExtensions[1];
            const unsigned char *ext = pToExtensions + 2;
            while (ext < pToExtensions + extensionsLen) {
                short extType = (ext[0] << 8) | ext[1];
                ext += 2;
                short extLen = (ext[0] << 8) | ext[1];
                ext += 2;
                debugs(83, 7, "SSL Exntension: " << std::hex << extType << " of size:" << extLen);
                //The SNI extension has the type 0 (extType == 0)
                // The two first bytes indicates the length of the SNI data (should be extLen-2)
                // The next byte is the hostname type, it should be '0' for normal hostname (ext[2] == 0)
                // The 3rd and 4th bytes are the length of the hostname
                if (extType == 0 && ext[2] == 0) {
                    int hostLen = (ext[3] << 8) | ext[4];
                    serverName.assign((const char *)(ext+5), hostLen);
                    debugs(83, 7, "Found server name: " << serverName);
                } else if (extType == 15 && ext[0] != 0) {
                    // The heartBeats are the type 15
                    doHeartBeats = true;
                } else
                    extensions.push_back(extType);

                ext += extLen;
            }
        }
    }
    return true;
}

bool
Ssl::Bio::sslFeatures::parseV23Hello(const unsigned char *hello)
{
#if defined(DO_SSLV23)
    debugs(83, 7, "Get fake features from v23 hello message.");
    sslVersion = (hello[3] << 8) | hello[4];
    debugs(83, 7, "Get fake features. Version :" << std::hex << std::setw(8) << std::setfill('0')<< sslVersion);

    // The following hello message size exist in 2nd byte
    int helloSize = hello[1];
    helloSize += 2; //Include the 2 header bytes.
    helloMessage.clear();
    helloMessage.append((char *)hello, helloSize);

    //Ciphers list. It is stored after the Session ID.

    int ciphersLen = (hello[5] << 8) | hello[6];
    const unsigned char *ciphers = hello + 11;
    if (ciphersLen) {
        const SSL_METHOD *method = SSLv23_method();
        int cs = method->put_cipher_by_char(NULL, NULL);
        assert(cs > 0);
        for (int i = 0; i < ciphersLen; i += cs) {
            // The v2 hello messages cipher has 3 bytes.
            // The v2 cipher has the first byte not null
            // Because we are going to sent only v3 message we
            // are ignoring these ciphers
            if (ciphers[i] != 0)
                continue;
            const SSL_CIPHER *c = method->get_cipher_by_char((ciphers + i + 1));
            if (c != NULL) {
                if (!clientRequestedCiphers.empty())
                    clientRequestedCiphers.append(":");
                clientRequestedCiphers.append(c->name);
            }
        }
    }
    debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

    //Get Client Random number. It starts on the position 11 of hello message
    memcpy(client_random, ciphers + ciphersLen, SSL3_RANDOM_SIZE);
    debugs(83, 7, "Client random: " <<  objToString(client_random, SSL3_RANDOM_SIZE));

    compressMethod = 0;
    return true;
#else
    return false;
#endif
}

void
Ssl::Bio::sslFeatures::applyToSSL(SSL *ssl) const
{
    // To increase the possibility for bumping after peek mode selection or
    // splicing after stare mode selection it is good to set the
    // SSL protocol version.
    // The SSL_set_ssl_method is not the correct method because it will strict
    // SSL version which can be used to the SSL version used for client hello message.
    // For example will prevent comunnicating with a tls1.0 server if the
    // client sent and tlsv1.2 Hello message.
    //SSL_set_ssl_method(ssl, Ssl::method(features.toSquidSSLVersion()));
#if defined(TLSEXT_NAMETYPE_host_name)
    if (!serverName.isEmpty()) {
        SSL_set_tlsext_host_name(ssl, serverName.c_str());
    }
#endif
    if (!clientRequestedCiphers.empty())
        SSL_set_cipher_list(ssl, clientRequestedCiphers.c_str());
#if defined(SSL_OP_NO_COMPRESSION) /* XXX: OpenSSL 0.9.8k lacks SSL_OP_NO_COMPRESSION */
    if (compressMethod == 0)
        SSL_set_options(ssl, SSL_OP_NO_COMPRESSION);
#endif

}

std::ostream &
Ssl::Bio::sslFeatures::print(std::ostream &os) const
{
    static std::string buf;
    return os << "v" << sslVersion <<
           " SNI:" << (serverName.isEmpty() ? SBuf("-") : serverName) <<
           " comp:" << compressMethod <<
           " Ciphers:" << clientRequestedCiphers <<
           " Random:" << objToString(client_random, SSL3_RANDOM_SIZE) <<
           " ecPointFormats:" << ecPointFormatList <<
           " ec:" << ellipticCurves <<
           " opaquePrf:" << opaquePrf;
}

#endif /* USE_SSL */

