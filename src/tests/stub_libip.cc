/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"

#define STUB_API "ip/libip.la"
#include "tests/STUB.h"

#include "ip/QosConfig.h"
namespace Ip
{
namespace Qos
{
void getTosFromServer(fde *, const int) {
#if USE_QOS_TOS
    STUB
#endif
}
void getNfmarkFromServer(const fde *, const fde *, const int) {
#if USE_QOS_NFMARK
    STUB
#endif
}
#if USE_QOS_NFMARK
int GetNfMarkCallback(enum nf_conntrack_msg_type, struct nf_conntrack *, void *) STUB_RETVAL(-1)
#endif
tos_t doTosLocalMiss(const int, const hier_code) STUB_RETVAL(-1)
int doNfmarkLocalMiss(const int, const hier_code) STUB_RETVAL(-1)
int doTosLocalHit(const int) STUB_RETVAL(-1)
int doNfmarkLocalHit(const int) STUB_RETVAL(-1)
void parseConfigLine() STUB
void dumpConfigLine(char *, const char *) STUB

Config::Config() {STUB}
bool Config::isAclNfmarkActive() const STUB_RETVAL(false)
bool Config::isAclTosActive() const STUB_RETVAL(false)
}
}

