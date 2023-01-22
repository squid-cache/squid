/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "ipc/Forwarder.cc"
#include "tests/STUB.h"

#include "ipc/Forwarder.h"
Ipc::Forwarder::Forwarder(Request::Pointer, double): AsyncJob("Ipc::Forwarder"), timeout(0) {STUB}
Ipc::Forwarder::~Forwarder() STUB
void Ipc::Forwarder::start() STUB
bool Ipc::Forwarder::doneAll() const STUB_RETVAL(false)
void Ipc::Forwarder::swanSong() STUB
void Ipc::Forwarder::callException(const std::exception &) STUB
void Ipc::Forwarder::handleError() STUB
void Ipc::Forwarder::handleTimeout() STUB
void Ipc::Forwarder::handleException(const std::exception &) STUB

