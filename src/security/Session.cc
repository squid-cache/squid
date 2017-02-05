/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS session management */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "Debug.h"
#include "fd.h"
#include "fde.h"
#include "ipc/MemMap.h"
#include "security/Session.h"
#include "SquidConfig.h"
#include "ssl/bio.h"

#define SSL_SESSION_ID_SIZE 32
#define SSL_SESSION_MAX_SIZE 10*1024

#if USE_OPENSSL || USE_GNUTLS
static int
tls_read_method(int fd, char *buf, int len)
{
    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if DONT_DO_THIS && USE_OPENSSL
    if (!SSL_is_init_finished(session)) {
        errno = ENOTCONN;
        return -1;
    }
#endif

#if USE_OPENSSL
    int i = SSL_read(session, buf, len);
#elif USE_GNUTLS
    int i = gnutls_record_recv(session, buf, len);
#endif

    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
        (void)VALGRIND_MAKE_MEM_DEFINED(buf, i);
    }

#if USE_OPENSSL
    if (i > 0 && SSL_pending(session) > 0) {
#elif USE_GNUTLS
    if (i > 0 && gnutls_record_check_pending(session) > 0) {
#endif
        debugs(83, 2, "TLS FD " << fd << " is pending");
        fd_table[fd].flags.read_pending = true;
    } else
        fd_table[fd].flags.read_pending = false;

    return i;
}

static int
tls_write_method(int fd, const char *buf, int len)
{
    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if USE_OPENSSL
    if (!SSL_is_init_finished(session)) {
        errno = ENOTCONN;
        return -1;
    }
#endif

#if USE_OPENSSL
    int i = SSL_write(session, buf, len);
#elif USE_GNUTLS
    int i = gnutls_record_send(session, buf, len);
#endif

    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
    }
    return i;
}
#endif

#if USE_OPENSSL
Security::SessionPointer
Security::NewSessionObject(const Security::ContextPointer &ctx)
{
    Security::SessionPointer session(SSL_new(ctx.get()), [](SSL *p) {
        debugs(83, 5, "SSL_free session=" << (void*)p);
        SSL_free(p);
    });
    debugs(83, 5, "SSL_new session=" << (void*)session.get());
    return session;
}
#endif

static bool
CreateSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &conn, Security::Io::Type type, const char *squidCtx)
{
    if (!Comm::IsConnOpen(conn)) {
        debugs(83, DBG_IMPORTANT, "Gone connection");
        return false;
    }

#if USE_OPENSSL || USE_GNUTLS

    const char *errAction = "with no TLS/SSL library";
    int errCode = 0;
#if USE_OPENSSL
    Security::SessionPointer session(Security::NewSessionObject(ctx));
    if (!session) {
        errCode = ERR_get_error();
        errAction = "failed to allocate handle";
    }
#elif USE_GNUTLS
    gnutls_session_t tmp;
    errCode = gnutls_init(&tmp, static_cast<unsigned int>(type) | GNUTLS_NONBLOCK);
    Security::SessionPointer session(tmp, [](gnutls_session_t p) {
        debugs(83, 5, "gnutls_deinit session=" << (void*)p);
        gnutls_deinit(p);
    });
    debugs(83, 5, "gnutls_init " << (type == Security::Io::BIO_TO_SERVER ? "client" : "server" )<< " session=" << (void*)session.get());
    if (errCode != GNUTLS_E_SUCCESS) {
        session.reset();
        errAction = "failed to initialize session";
    }
#endif

    if (session) {
        const int fd = conn->fd;

#if USE_OPENSSL
        // without BIO, we would call SSL_set_fd(ssl.get(), fd) instead
        if (BIO *bio = Ssl::Bio::Create(fd, type)) {
            Ssl::Bio::Link(session.get(), bio); // cannot fail
#elif USE_GNUTLS
        errCode = gnutls_credentials_set(session.get(), GNUTLS_CRD_CERTIFICATE, ctx.get());
        if (errCode == GNUTLS_E_SUCCESS) {

            if (auto *peer = conn->getPeer())
                peer->secure.updateSessionOptions(session);
            else
                Security::ProxyOutgoingConfig.updateSessionOptions(session);

            // NP: GnuTLS does not yet support the BIO operations
            //     this does the equivalent of SSL_set_fd() for now.
            gnutls_transport_set_int(session.get(), fd);
            gnutls_handshake_set_timeout(session.get(), GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif

            debugs(83, 5, "link FD " << fd << " to TLS session=" << (void*)session.get());
            fd_table[fd].ssl = session;
            fd_table[fd].read_method = &tls_read_method;
            fd_table[fd].write_method = &tls_write_method;
            fd_note(fd, squidCtx);
            return true;
        }

#if USE_OPENSSL
        errCode = ERR_get_error();
        errAction = "failed to initialize I/O";
#elif USE_GNUTLS
        errAction = "failed to assign credentials";
#endif
    }

    debugs(83, DBG_IMPORTANT, "ERROR: " << squidCtx << ' ' << errAction <<
           ": " << (errCode != 0 ? Security::ErrorString(errCode) : ""));
#endif
    return false;
}

bool
Security::CreateClientSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, const char *squidCtx)
{
    return CreateSession(ctx, c, Security::Io::BIO_TO_SERVER, squidCtx);
}

bool
Security::CreateServerSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, const char *squidCtx)
{
    return CreateSession(ctx, c, Security::Io::BIO_TO_CLIENT, squidCtx);
}

void
Security::SessionSendGoodbye(const Security::SessionPointer &s)
{
    debugs(83, 5, "session=" << (void*)s.get());
    if (s) {
#if USE_OPENSSL
        SSL_shutdown(s.get());
#elif USE_GNUTLS
        gnutls_bye(s.get(), GNUTLS_SHUT_RDWR);
#endif
    }
}

bool
Security::SessionIsResumed(const Security::SessionPointer &s)
{
    bool result = false;
#if USE_OPENSSL
    result = SSL_session_reused(s.get()) == 1;
#elif USE_GNUTLS
    result = gnutls_session_is_resumed(s.get()) != 0;
#endif
    debugs(83, 7, "session=" << (void*)s.get() << ", query? answer: " << (result ? 'T' : 'F') );
    return result;
}

void
Security::MaybeGetSessionResumeData(const Security::SessionPointer &s, Security::SessionStatePointer &data)
{
    if (!SessionIsResumed(s)) {
#if USE_OPENSSL
        // nil is valid for SSL_get1_session(), it cannot fail.
        data.reset(SSL_get1_session(s.get()));
#elif USE_GNUTLS
        gnutls_datum_t *tmp = nullptr;
        const auto x = gnutls_session_get_data2(s.get(), tmp);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " error: " << Security::ErrorString(x));
        }
        data.reset(tmp);
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get() << ", do nothing.");
    }
}

void
Security::SetSessionResumeData(const Security::SessionPointer &s, const Security::SessionStatePointer &data)
{
    if (data) {
#if USE_OPENSSL
        if (!SSL_set_session(s.get(), data.get())) {
            const auto ssl_error = ERR_get_error();
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(ssl_error));
        }
#elif USE_GNUTLS
        const auto x = gnutls_session_set_data(s.get(), data->data, data->size);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(x));
        }
#else
        // critical because, how did it get here?
        debugs(83, DBG_CRITICAL, "no TLS library. session=" << (void*)s.get() << " data=" << (void*)data.get());
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " no resume data");
    }
}

static bool
isTlsServer()
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.encryptTransport)
            return true;
        if (s->flags.tunnelSslBumping)
            return true;
    }

    return false;
}

void
initializeSessionCache()
{
#if USE_OPENSSL
    // Check if the MemMap keys and data are enough big to hold
    // session ids and session data
    assert(SSL_SESSION_ID_SIZE >= MEMMAP_SLOT_KEY_SIZE);
    assert(SSL_SESSION_MAX_SIZE >= MEMMAP_SLOT_DATA_SIZE);

    int configuredItems = ::Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot);
    if (IamWorkerProcess() && configuredItems)
        Ssl::SessionCache = new Ipc::MemMap(Ssl::SessionCacheName);
    else {
        Ssl::SessionCache = nullptr;
        return;
    }

    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.staticContext)
            Ssl::SetSessionCallbacks(s->secure.staticContext);
    }
#endif
}

/// initializes shared memory segments used by MemStore
class SharedSessionCacheRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    SharedSessionCacheRr(): owner(nullptr) {}
    virtual void useConfig();
    virtual ~SharedSessionCacheRr();

protected:
    virtual void create();

private:
    Ipc::MemMap::Owner *owner;
};

RunnerRegistrationEntry(SharedSessionCacheRr);

void
SharedSessionCacheRr::useConfig()
{
#if USE_OPENSSL // while Ssl:: bits in use
    if (Ssl::SessionCache || !isTlsServer()) //no need to configure ssl session cache.
        return;

    Ipc::Mem::RegisteredRunner::useConfig();
    initializeSessionCache();
#endif
}

void
SharedSessionCacheRr::create()
{
    if (!isTlsServer()) //no need to configure ssl session cache.
        return;

#if USE_OPENSSL // while Ssl:: bits in use
    if (int items = Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot))
        owner = Ipc::MemMap::Init(Ssl::SessionCacheName, items);
#endif
}

SharedSessionCacheRr::~SharedSessionCacheRr()
{
    // XXX: Enable after testing to reduce at-exit memory "leaks".
    // delete Ssl::SessionCache;

    delete owner;
}

