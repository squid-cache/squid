/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "stub_main_cc.cc"
#include "tests/STUB.h"

void shut_down(int) STUB
void reconfigure(int) STUB
void rotate_logs(int) STUB

