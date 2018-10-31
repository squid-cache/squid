/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "errorpage.h"

#define STUB_API "errorpage.cc"
#include "tests/STUB.h"

err_type errorReservePageId(const char *page_name) STUB_RETVAL(err_type())
void errorAppendEntry(StoreEntry * entry, ErrorState * err) STUB
bool strHdrAcptLangGetItem(const String &hdr, char *lang, int langLen, size_t &pos) STUB_RETVAL(false)
void TemplateFile::loadDefault() STUB
TemplateFile::TemplateFile(char const*, err_type) STUB
bool TemplateFile::loadFor(const HttpRequest *) STUB_RETVAL(false)
bool ErrorState::IsDenyInfoUrl(const char *) STUB_RETVAL(false)
ErrTextValidator &ErrTextValidator::useCfgContext(const char *filename, int lineNo, const char *line) STUB_RETVAL(*this)
bool ErrTextValidator::validate(char const*) STUB_RETVAL(false)
