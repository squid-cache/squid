/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "eui/libeui.la"
#include "STUB.h"

#include "eui/Config.h"
Eui::EuiConfig Eui::TheConfig;

#include "eui/Eui48.h"
#if USE_SQUID_EUI
const unsigned char *Eui::Eui48::get(void) STUB_RETVAL(NULL)
bool Eui::Eui48::decode(const char *asc) STUB_RETVAL(false)
bool Eui::Eui48::encode(char *buf, const int len) const STUB_RETVAL(false)
bool Eui::Eui48::lookup(const Ip::Address &c) STUB_RETVAL(false)
#endif

#include "eui/Eui64.h"
#if USE_SQUID_EUI
const unsigned char *Eui::Eui64::get(void) STUB_RETVAL(NULL)
bool Eui::Eui64::decode(const char *asc) STUB_RETVAL(false)
bool Eui::Eui64::encode(char *buf, const int len) const STUB_RETVAL(false)
bool Eui::Eui64::lookup(const Ip::Address &c) STUB_RETVAL(false)
bool Eui::Eui64::lookupNdp(const Ip::Address &c) STUB_RETVAL(false)
bool Eui::Eui64::lookupSlaac(const Ip::Address &c) STUB_RETVAL(false)
#endif

