/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/ServiceRep.h"
#include "ConfigParser.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "Store.h"
#include "wordlist.h"

Adaptation::Icap::Config Adaptation::Icap::TheConfig;

Adaptation::Icap::Config::Config() :
    default_options_ttl(0),
    preview_enable(0), preview_size(0), allow206_enable(0),
    connect_timeout_raw(0), io_timeout_raw(0), reuse_connections(0),
    client_username_header(NULL), client_username_encode(0), repeat(NULL),
    repeat_limit(0)
{
}

Adaptation::Icap::Config::~Config()
{
    // no need to free client_username_header, it's done in cf_parser.cci:free_all
}

Adaptation::ServicePointer
Adaptation::Icap::Config::createService(const ServiceConfigPointer &cfg)
{
    return new Adaptation::Icap::ServiceRep(cfg);
}

time_t Adaptation::Icap::Config::connect_timeout(bool bypassable) const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw; // explicitly configured

    return bypassable ? ::Config.Timeout.peer_connect : ::Config.Timeout.connect;
}

time_t Adaptation::Icap::Config::io_timeout(bool) const
{
    if (io_timeout_raw > 0)
        return io_timeout_raw; // explicitly configured
    // TODO: provide a different default for an ICAP transaction that
    // can still be bypassed
    return ::Config.Timeout.read;
}

