#ifndef SQUID_SSL_CONTEXT_STORAGE_H
#define SQUID_SSL_CONTEXT_STORAGE_H

#if USE_SSL

#include "SquidTime.h"
#include "CacheManager.h"
#include "ip/Address.h"
#include "mgr/Action.h"
#include "mgr/Command.h"
#if HAVE_MAP
#include <map>
#endif
#if HAVE_LIST
#include <list>
#endif
#include <openssl/ssl.h>

/// TODO: Replace on real size.
#define SSL_CTX_SIZE 1024

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
    virtual void dump (StoreEntry *sentry);
    /**
     * We do not support aggregation of information across workers
     * TODO: aggregate these stats
     */
    virtual bool aggregatable() const { return false; }
};

/**
 * Memory cache for store generated SSL context. Enforces total size limits
 * using an LRU algorithm.
 */
class LocalContextStorage
{
    friend class CertificateStorageAction;
public:
    /// Cache item is an (SSL_CTX, host name) tuple.
    class Item
    {
    public:
        Item(SSL_CTX * aSsl_ctx, std::string const & aName);
        ~Item();
    public:
        SSL_CTX * ssl_ctx; ///< The SSL context.
        std::string host_name; ///< The host name of the SSL context.
    };

    typedef std::list<Item *> Queue;
    typedef Queue::iterator QueueIterator;

    /// host_name:queue_item mapping for fast lookups by host name
    typedef std::map<std::string, QueueIterator> Map;
    typedef Map::iterator MapIterator;
    typedef std::pair<std::string, QueueIterator> MapPair;

    LocalContextStorage(size_t aMax_memory);
    ~LocalContextStorage();
    /// Set maximum memory size for this storage.
    void SetSize(size_t aMax_memory);
    /// Return a pointer to the  added ssl_ctx or NULL if fails (eg. max cache size equal 0).
    SSL_CTX * add(char const * host_name, SSL_CTX * ssl_ctx);
    /// Find SSL_CTX in storage by host name. Lru queue will be updated.
    SSL_CTX * find(char const * host_name);
    void remove(char const * host_name); ///< Delete the SSL context by hostname

private:
    void purgeOne(); ///< Delete oldest object.
    /// Delete object by iterator. It is used in deletePurge() and remove(...) methods.
    void deleteAt(MapIterator i);

    size_t max_memory; ///< Max cache size.
    size_t memory_used; ///< Used cache size.
    Map storage; ///< The hostnames/SSL_CTX * pairs
    Queue lru_queue; ///< LRU cache index
};

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
    LocalContextStorage & getLocalStorage(Ip::Address const & address);
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
#endif // USE_SSL

#endif // SQUID_SSL_CONTEXT_STORAGE_H
