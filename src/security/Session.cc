/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/RunnersRegistry.h"
#include "ipc/MemMap.h"
#include "security/Session.h"
#include "SquidConfig.h"

#define SSL_SESSION_ID_SIZE 32
#define SSL_SESSION_MAX_SIZE 10*1024

#if USE_GNUTLS
void
squid_datum_free(gnutls_datum_t *D) {
    gnutls_free(D);
}
#endif

bool
Security::SessionIsResumed(const Security::SessionPointer &s)
{
    return
#if USE_OPENSSL
        SSL_session_reused(s.get()) == 1;
#elif USE_GNUTLS
        gnutls_session_is_resumed(s.get()) != 0;
#else
        false;
#endif
}

void
Security::GetSessionResumeData(const Security::SessionPointer &s, Security::SessionStatePointer &data)
{
    if (!SessionIsResumed(s)) {
#if USE_OPENSSL
        data.reset(SSL_get1_session(s.get()));
#elif USE_GNUTLS
        gnutls_datum_t *tmp = nullptr;
        (void)gnutls_session_get_data2(s.get(), tmp);
        data.reset(tmp);
#endif
    }
}

void
Security::SetSessionResumeData(const Security::SessionPtr &s, const Security::SessionStatePointer &data)
{
    if (s) {
#if USE_OPENSSL
        (void)SSL_set_session(s, data.get());
#elif USE_GNUTLS
        (void)gnutls_session_set_data(s, data->data, data->size);
#endif
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
        if (s->secure.staticContext.get())
            Ssl::SetSessionCallbacks(s->secure.staticContext.get());
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

