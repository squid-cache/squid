/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "url.cc"
#include "tests/STUB.h"

#include "URL.h"
URL::URL(AnyP::UriScheme const &) {STUB}
void URL::touch() STUB
bool URL::parse(const HttpRequestMethod&, char *) STUB_RETVAL(true)
void URL::host(const char *) STUB
static SBuf nil;
const SBuf &URL::path() const STUB_RETVAL(nil)
const SBuf &URL::SlashPath()
{
    static SBuf slash("/");
    return slash;
}
const SBuf &URL::Asterisk()
{
    static SBuf asterisk("*");
    return asterisk;
}
SBuf &URL::authority(bool) const STUB_RETVAL(nil)
SBuf &URL::absolute() const STUB_RETVAL(nil)
void urlInitialize() STUB
char *urlCanonicalClean(const HttpRequest *) STUB_RETVAL(nullptr)
const char *urlCanonicalFakeHttps(const HttpRequest *) STUB_RETVAL(nullptr)
bool urlIsRelative(const char *) STUB_RETVAL(false)
char *urlMakeAbsolute(const HttpRequest *, const char *)STUB_RETVAL(nullptr)
char *urlRInternal(const char *, unsigned short, const char *, const char *) STUB_RETVAL(nullptr)
char *urlInternal(const char *, const char *) STUB_RETVAL(nullptr)
int matchDomainName(const char *, const char *, uint) STUB_RETVAL(0)
int urlCheckRequest(const HttpRequest *) STUB_RETVAL(0)
char *urlHostname(const char *) STUB_RETVAL(nullptr)
void urlExtMethodConfigure() STUB

