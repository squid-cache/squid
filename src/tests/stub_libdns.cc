/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "dns/libdns.la"
#include "tests/STUB.h"

#include "dns/LookupDetails.h"

std::ostream &Dns::LookupDetails::print(std::ostream &os) const STUB_RETVAL(os)
