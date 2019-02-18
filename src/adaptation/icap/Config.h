/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPCONFIG_H
#define SQUID_ICAPCONFIG_H

#include "acl/forward.h"
#include "adaptation/Config.h"
#include "adaptation/icap/ServiceRep.h"
#include "base/AsyncCall.h"
#include "event.h"

namespace Adaptation
{
namespace Icap
{

class ConfigParser;

class Config: public Adaptation::Config
{

public:
    int default_options_ttl;
    int preview_enable;
    int preview_size;
    int allow206_enable;
    time_t connect_timeout_raw;
    time_t io_timeout_raw;
    int reuse_connections;
    char* client_username_header;
    int client_username_encode;
    acl_access *repeat; ///< icap_retry ACL in squid.conf
    int repeat_limit; ///< icap_retry_limit in squid.conf

    Config();
    ~Config();

    time_t connect_timeout(bool bypassable) const;
    time_t io_timeout(bool bypassable) const;

private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented

    virtual Adaptation::ServicePointer createService(const ServiceConfigPointer &cfg);
};

extern Config TheConfig;

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPCONFIG_H */

