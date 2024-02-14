/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_CONTEXT_STORAGE_H
#define SQUID_SRC_SSL_CONTEXT_STORAGE_H

#if USE_OPENSSL

#include "base/ClpMap.h"
#include "CacheManager.h"
#include "compat/openssl.h"
#include "ip/Address.h"
#include "mgr/Action.h"
#include "mgr/Command.h"
#include "security/forward.h"
#include "ssl/gadgets.h"

#include <list>
#include <map>
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

namespace  Ssl
{

/** Reports cached SSL certificate stats to Cache Manager.
 * TODO: Use "Report" functions instead friend class.
 */
class CertificateStorageAction : public Mgr::Action
{
public:
    CertificateStorageAction(const Mgr::Command::Pointer &cmd);
    static Pointer Create(const Mgr::Command::Pointer &cmd);
    void dump (StoreEntry *sentry) override;
    /**
     * We do not support aggregation of information across workers
     * TODO: aggregate these stats
     */
    bool aggregatable() const override { return false; }
};

inline uint64_t MemoryUsedByContext(const Security::ContextPointer &) {
    return 1024; // TODO: Calculate approximate memory usage by the context.
}
using LocalContextStorage = ClpMap<SBuf, Security::ContextPointer, MemoryUsedByContext>;

/// Class for storing/manipulating LocalContextStorage per local listening address/port.
class GlobalContextStorage
{
    friend class CertificateStorageAction;
public:
    GlobalContextStorage();
    ~GlobalContextStorage();
    /// Create new SSL context storage for the local listening address/port.
    void addLocalStorage(Ip::Address const & address, size_t size_of_store);
    /// Return the local storage for the given listening address/port.
    LocalContextStorage *getLocalStorage(Ip::Address const & address);
    /// When reconfigring should be called this method.
    void reconfigureStart();
private:
    /// Called by getLocalStorage method
    void reconfigureFinish();
    bool reconfiguring; ///< True if system reconfiguring now.
    /// Storage used on configure or reconfigure.
    std::map<Ip::Address, size_t> configureStorage;
    /// Map for storing all local ip address and their local storages.
    std::map<Ip::Address, LocalContextStorage *> storage;
};

/// Global cache for store all SSL server certificates.
extern GlobalContextStorage TheGlobalContextStorage;
} //namespace Ssl
#endif // USE_OPENSSL

#endif /* SQUID_SRC_SSL_CONTEXT_STORAGE_H */

