/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mgr/Registration.h"
#include "ssl/context_storage.h"
#include "Store.h"
#include "StoreEntryStream.h"

#include <limits>
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &aCmd)
    :   Mgr::Action(aCmd)
{}

Ssl::CertificateStorageAction::Pointer
Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &aCmd)
{
    return new CertificateStorageAction(aCmd);
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
        stream << ssl_store_policy.memLimit() / 1024 << delimiter;
        stream << ssl_store_policy.entries() << delimiter;
        stream << SSL_CTX_SIZE / 1024 << delimiter;
        stream << ssl_store_policy.size() / 1024 << delimiter;
        stream << ssl_store_policy.freeMem() / 1024 << endString;
    }
    stream << endString;
    stream.flush();
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

Ssl::LocalContextStorage *Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const & address)
{
    reconfigureFinish();
    std::map<Ip::Address, LocalContextStorage *>::iterator i = storage.find(address);

    if (i == storage.end())
        return NULL;
    else
        return i->second;
}

void Ssl::GlobalContextStorage::reconfigureStart()
{
    configureStorage.clear();
    reconfiguring = true;
}

void Ssl::GlobalContextStorage::reconfigureFinish()
{
    if (reconfiguring) {
        reconfiguring = false;

        // remove or change old local storages.
        for (std::map<Ip::Address, LocalContextStorage *>::iterator i = storage.begin(); i != storage.end();) {
            std::map<Ip::Address, size_t>::iterator conf_i = configureStorage.find(i->first);
            if (conf_i == configureStorage.end() || conf_i->second <= 0) {
                delete i->second;
                storage.erase(i++);
            } else {
                i->second->setMemLimit(conf_i->second);
                ++i;
            }
        }

        // add new local storages.
        for (std::map<Ip::Address, size_t>::iterator conf_i = configureStorage.begin(); conf_i != configureStorage.end(); ++conf_i ) {
            if (storage.find(conf_i->first) == storage.end() && conf_i->second > 0) {
                storage.insert(std::pair<Ip::Address, LocalContextStorage *>(conf_i->first, new LocalContextStorage(-1, conf_i->second)));
            }
        }
    }
}

Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;

