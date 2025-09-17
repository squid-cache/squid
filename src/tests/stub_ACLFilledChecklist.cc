/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "acl/FilledChecklist.cc"
#include "tests/STUB.h"

#include "ExternalACLEntry.h"

#include "acl/FilledChecklist.h"
// These stubs are not in tests/stub_acl.cc because ACLFilledChecklist requires
// X509_free() and other heavy or difficult-to-stub dependencies that other
// tests/stub_acl.cc users (e.g., testConfigParser) may not otherwise need.
ACLFilledChecklist::ACLFilledChecklist() STUB
ACLFilledChecklist::ACLFilledChecklist(const acl_access *, HttpRequest *) STUB
ACLFilledChecklist::~ACLFilledChecklist() STUB
void ACLFilledChecklist::syncAle(HttpRequest *, const char *) const STUB
void ACLFilledChecklist::updateAle(const AccessLogEntry::Pointer &) STUB
void ACLFilledChecklist::updateReply(const HttpReply::Pointer &) STUB
void ACLFilledChecklist::verifyAle() const STUB
