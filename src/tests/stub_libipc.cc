/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "stub_libipc.cc"
#include "tests/STUB.h"

#include "ipc/Inquirer.h"
Ipc::Inquirer::~Inquirer() STUB_NOP
void Ipc::Inquirer::swanSong() STUB
void Ipc::Inquirer::inquire() STUB
void Ipc::Inquirer::handleRemoteAck(Response::Pointer) STUB
bool Ipc::Inquirer::doneAll() const STUB
void Ipc::Inquirer::handleException(const std::exception&) STUB
void Ipc::Inquirer::callException(const std::exception&) STUB
void Ipc::Inquirer::start() STUB
const char*Ipc::Inquirer::status() const STUB
void Ipc::Inquirer::cleanup() STUB