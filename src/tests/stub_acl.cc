/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Gadgets.h"

#define STUB_API "acl/"
#include "tests/STUB.h"

size_t aclParseAclList(ConfigParser &, Acl::Tree **, const char *) STUB_RETVAL(0)

