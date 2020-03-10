/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "cfg/libcfg.la"
#include "tests/STUB.h"

#include "cfg/Exceptions.h"
namespace Cfg
{
const char *FatalError::what() const throw() STUB_RETVAL("")
void RequireValue(const char *, const char *) STUB
}
