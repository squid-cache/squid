/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem_node.h"

#define STUB_API "mem_node.cc"
#include "tests/STUB.h"

mem_node::mem_node(int64_t offset):nodeBuffer(0,offset,data) STUB
    size_t mem_node::InUseCount() STUB_RETVAL(0)

