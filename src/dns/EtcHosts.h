/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DNS_ETCHOSTS_H
#define SQUID_SRC_DNS_ETCHOSTS_H

#include "base/RunnersRegistry.h"
#include "configuration/forward.h"
#include "dns/forward.h"
#include "sbuf/SBuf.h"

namespace Dns
{

/// specialized parser for /etc/hosts file
class EtcHosts : public RegisteredRunner
{
public:
    /// squid.conf etc_hosts setting (if any)
    static SBuf Path;

    ~EtcHosts() { clear(); }

    /* RegisteredRunner API */
    void finalizeConfig() override { parse(); }
    void startReconfigure() override { clear(); }
    void syncConfig() override { parse(); }

private:
    void parse();
    void clear();

    Configuration::File *etcHostsFile = nullptr;
};

} // namespace Dns

#endif /* SQUID_SRC_DNS_ETCHOSTS_H */
