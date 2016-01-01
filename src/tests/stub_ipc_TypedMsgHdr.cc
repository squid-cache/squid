/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "TypedMsgHdr.cc"
#include "tests/STUB.h"

#include "ipc/TypedMsgHdr.h"

Ipc::TypedMsgHdr::TypedMsgHdr() STUB
void Ipc::TypedMsgHdr::checkType(int) const STUB
void Ipc::TypedMsgHdr::setType(int) STUB
void Ipc::TypedMsgHdr::getFixed(void*, size_t) const STUB
void Ipc::TypedMsgHdr::putFixed(void const*, size_t) STUB
void Ipc::TypedMsgHdr::getString(String&) const STUB
void Ipc::TypedMsgHdr::putString(String const&) STUB

