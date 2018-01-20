/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ipc/UdsOp.h"

#define STUB_API "UdsOp.cc"
#include "tests/STUB.h"

void Ipc::SendMessage(const String& toAddress, const TypedMsgHdr& message) STUB

