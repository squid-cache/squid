/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "ip/QosConfig.h"
#include "Store.h"

void
Ip::Qos::getTosFromServer(fde *clientFde, const int server_fd)
{
#if USE_QOS_TOS
    fatal ("Not implemented");
#endif
}

void Ip::Qos::getNfmarkFromServer(const fde *clientFde, const fde *servFde, const int server_fd)
{
#if USE_QOS_NFMARK
    fatal ("Not implemented");
#endif
}

#if USE_QOS_NFMARK
int
Ip::Qos::GetNfMarkCallback(enum nf_conntrack_msg_type type,
                           struct nf_conntrack *ct,
                           void *data)
{
    fatal ("Not implemented");
}
#endif

tos_t
Ip::Qos::doTosLocalMiss(const int fd, const hier_code hierCode) const
{
    fatal ("Not implemented");
}

int
Ip::Qos::doNfmarkLocalMiss(const int fd, const hier_code hierCode) const
{
    fatal ("Not implemented");
}

int
Ip::Qos::doTosLocalHit(const int fd) const
{
    fatal ("Not implemented");
}

int
Ip::Qos::doNfmarkLocalHit(const int fd) const
{
    fatal ("Not implemented");
}

Ip::Qos::Config()
{
    fatal ("Not implemented");
}

Ip::Qos::~Config()
{
    fatal ("Not implemented");
}

void
Ip::Qos::parseConfigLine()
{
    fatal ("Not implemented");
}

void
Ip::Qos::dumpConfigLine(char *entry, const char *name)
{
    fatal ("Not implemented");
}

#if !_USE_INLINE_
#include "Qos.cci"
#endif
