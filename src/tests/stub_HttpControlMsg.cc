/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "HttpControlMsg.cc"
#include "tests/STUB.h"

#include "HttpControlMsg.h"
void HttpControlMsgSink::wroteControlMsg(CommIoCbParams const&) STUB
void HttpControlMsgSink::doneWithControlMsg() STUB

