#include "squid.h"
#include "Store.h"
#include "StoreEntryStream.h"
#include "ssl/context_storage.h"
#include "mgr/Registration.h"
#if HAVE_LIMITS
#include <limits>
#endif
#if USE_SSL
#include <openssl/ssl.h>
#endif

Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &cmd)
        :   Mgr::Action(cmd)
{}

Ssl::CertificateStorageAction::Pointer
Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &cmd)
{
    return new CertificateStorageAction(cmd);
}

void Ssl::CertificateStorageAction::dump (StoreEntry *sentry)
{
    StoreEntryStream stream(sentry);
    const char delimiter = '\t';
    const char endString = '\n';
    // Page title.
    stream << "Cached ssl certificates statistic.\n";
    // Title of statistic table.
    stream << "Port" << delimiter << "Max mem(KB)" << delimiter << "Cert number" << delimiter << "KB/cert" << delimiter << "Mem used(KB)" << delimiter << "Mem free(KB)" << endString;

    // Add info for each port.
    for (std::map<Ip::Address, LocalContextStorage *>::iterator i = TheGlobalContextStorage.storage.begin(); i != TheGlobalContextStorage.storage.end(); ++i) {
        stream << i->first << delimiter;
        LocalContextStorage & ssl_store_policy(*(i->second));
        stream << ssl_store_policy.max_memory / 1024 << delimiter;
        stream << ssl_store_policy.memory_used / SSL_CTX_SIZE << delimiter;
        stream << SSL_CTX_SIZE / 1024 << delimiter;
        stream << ssl_store_policy.memory_used / 1024 << delimiter;
        stream << (ssl_store_policy.max_memory - ssl_store_policy.memory_used) / 1024 << endString;
    }
    stream << endString;
    stream.flush();
}

Ssl::LocalContextStorage::LocalContextStorage(size_t aMax_memory)
        :   max_memory(aMax_memory), memory_used(0)
{}

Ssl::LocalContextStorage::~LocalContextStorage()
{
    for (QueueIterator i = lru_queue.begin(); i != lru_queue.end(); ++i) {
        delete *i;
    }
}

SSL_CTX * Ssl::LocalContextStorage::add(const char * host_name, SSL_CTX * ssl_ctx)
{
    if (max_memory < SSL_CTX_SIZE) {
        return NULL;
    }
    remove(host_name);
    while (SSL_CTX_SIZE + memory_used > max_memory) {
        purgeOne();
    }
    lru_queue.push_front(new Item(ssl_ctx, host_name));
    storage.insert(MapPair(host_name, lru_queue.begin()));
    memory_used += SSL_CTX_SIZE;
    return ssl_ctx;
}

SSL_CTX * Ssl::LocalContextStorage::find(char const * host_name)
{
    MapIterator i = storage.find(host_name);
    if (i == storage.end()) {
        return NULL;
    }
    lru_queue.push_front(*(i->second));
    lru_queue.erase(i->second);
    i->second = lru_queue.begin();
    return (*lru_queue.begin())->ssl_ctx;
}

void Ssl::LocalContextStorage::remove(char const * host_name)
{
    deleteAt(storage.find(host_name));
}

void Ssl::LocalContextStorage::purgeOne()
{
    QueueIterator i = lru_queue.end();
    --i;
    if (i != lru_queue.end()) {
        remove((*i)->host_name.c_str());
    }
}

void Ssl::LocalContextStorage::deleteAt(LocalContextStorage::MapIterator i)
{
    if (i != storage.end()) {

        delete *(i->second);
        lru_queue.erase(i->second);
        storage.erase(i);
        memory_used -= SSL_CTX_SIZE;
    }
}

void Ssl::LocalContextStorage::SetSize(size_t aMax_memory)
{
    max_memory = aMax_memory;
}

Ssl::LocalContextStorage::Item::Item(SSL_CTX * aSsl_ctx, std::string const & aName)
        :   ssl_ctx(aSsl_ctx), host_name(aName)
{}

Ssl::LocalContextStorage::Item::~Item()
{
    SSL_CTX_free(ssl_ctx);
}

///////////////////////////////////////////////////////

Ssl::GlobalContextStorage::GlobalContextStorage()
        :   reconfiguring(true)
{
    RegisterAction("cached_ssl_cert", "Statistic of cached generated ssl certificates", &CertificateStorageAction::Create, 0, 1);
}

Ssl::GlobalContextStorage::~GlobalContextStorage()
{
    for (std::map<Ip::Address, LocalContextStorage *>::iterator i = storage.begin(); i != storage.end(); ++i) {
        delete i->second;
    }
}

void Ssl::GlobalContextStorage::addLocalStorage(Ip::Address const & address, size_t size_of_store)
{
    assert(reconfiguring);
    configureStorage.insert(std::pair<Ip::Address, size_t>(address, size_of_store));
}

Ssl::LocalContextStorage & Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const & address)
{
    reconfigureFinish();
    std::map<Ip::Address, LocalContextStorage *>::iterator i = storage.find(address);
    assert (i != storage.end());
    return *(i->second);
}

void Ssl::GlobalContextStorage::reconfigureStart()
{
    reconfiguring = true;
}

void Ssl::GlobalContextStorage::reconfigureFinish()
{
    if (reconfiguring) {
        reconfiguring = false;

        // remove or change old local storages.
        for (std::map<Ip::Address, LocalContextStorage *>::iterator i = storage.begin(); i != storage.end(); ++i) {
            std::map<Ip::Address, size_t>::iterator conf_i = configureStorage.find(i->first);
            if (conf_i == configureStorage.end()) {
                storage.erase(i);
            } else {
                i->second->SetSize(conf_i->second);
            }
        }

        // add new local storages.
        for (std::map<Ip::Address, size_t>::iterator conf_i = configureStorage.begin(); conf_i != configureStorage.end(); ++conf_i ) {
            if (storage.find(conf_i->first) == storage.end()) {
                storage.insert(std::pair<Ip::Address, LocalContextStorage *>(conf_i->first, new LocalContextStorage(conf_i->second)));
            }
        }
    }
}

Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;
