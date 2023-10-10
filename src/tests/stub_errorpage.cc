/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpReply.h"

#define STUB_API "errorpage.cc"
#include "tests/STUB.h"

#include "errorpage.h"
CBDATA_CLASS_INIT(ErrorState);
ErrorState::ErrorState(err_type, Http::StatusCode, HttpRequest *, const AccessLogEntryPointer &) STUB
ErrorState::ErrorState(HttpRequest *, HttpReply *, const AccessLogEntryPointer &) STUB
ErrorState::~ErrorState() STUB
ErrorState *ErrorState::NewForwarding(err_type, HttpRequestPointer &, const AccessLogEntryPointer &) STUB_RETVAL(nullptr)
HttpReply *ErrorState::BuildHttpReply(void) STUB_RETVAL(nullptr)
void ErrorState::validate() STUB
void errorInitialize(void) STUB
void errorClean(void) STUB
void errorSend(const Comm::ConnectionPointer &, ErrorState *) STUB
void errorAppendEntry(StoreEntry *, ErrorState * ) STUB
err_type errorReservePageId(const char *, const SBuf &) STUB_RETVAL(err_type(0))
const char *errorPageName(int) STUB_RETVAL(nullptr)
TemplateFile::TemplateFile(char const*, err_type) STUB
void TemplateFile::loadDefault() STUB
bool TemplateFile::loadFor(const HttpRequest *) STUB_RETVAL(false)
bool TemplateFile::loadFromFile(const char *) STUB_RETVAL(false)
bool TemplateFile::tryLoadTemplate(const char *) STUB_RETVAL(false)
bool strHdrAcptLangGetItem(const String &, char *, int, size_t &) STUB_RETVAL(false)
std::ostream &operator <<(std::ostream &os, const ErrorState *) STUB_RETVAL(os)

