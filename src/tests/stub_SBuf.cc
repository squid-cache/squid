/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "SBuf.cc"
#include "tests/STUB.h"

#include "sbuf/SBuf.h"

InstanceIdDefinitions(SBuf, "SBuf");

SBufStats SBuf::stats;
const SBuf::size_type SBuf::npos;
const SBuf::size_type SBuf::maxSize;

std::ostream& SBufStats::dump(std::ostream &os) const STUB_RETVAL(os)
SBufStats& SBufStats::operator +=(const SBufStats&) STUB_RETVAL(*this)

SBuf::SBuf() {}
SBuf::SBuf(const SBuf &) {}
SBuf::SBuf(const char *, size_type) {}
SBuf::SBuf(const char *) {}
SBuf::SBuf(const std::string &) {}
SBuf::~SBuf() {}
SBuf& SBuf::assign(const SBuf &) STUB_RETVAL(*this)
SBuf& SBuf::assign(const char *, size_type) STUB_RETVAL(*this)
void SBuf::clear() STUB
SBuf& SBuf::append(const SBuf &) STUB_RETVAL(*this)
SBuf& SBuf::append(const char *, size_type) STUB_RETVAL(*this)
SBuf& SBuf::append(const char) STUB_RETVAL(*this)
SBuf& SBuf::Printf(const char *, ...) STUB_RETVAL(*this)
SBuf& SBuf::appendf(const char *, ...) STUB_RETVAL(*this)
SBuf& SBuf::vappendf(const char *, va_list) STUB_RETVAL(*this)
std::ostream& SBuf::print(std::ostream &os) const STUB_RETVAL(os)
std::ostream& SBuf::dump(std::ostream &os) const STUB_RETVAL(os)
void SBuf::setAt(size_type, char) STUB
int SBuf::compare(const SBuf &, const SBufCaseSensitive, const size_type) const STUB_RETVAL(-1)
int SBuf::compare(const char *, const SBufCaseSensitive, const size_type) const STUB_RETVAL(-1)
bool SBuf::startsWith(const SBuf &, const SBufCaseSensitive) const STUB_RETVAL(false)
bool SBuf::operator ==(const SBuf &) const STUB_RETVAL(false)
bool SBuf::operator !=(const SBuf &) const STUB_RETVAL(false)
SBuf SBuf::consume(size_type) STUB_RETVAL(*this)
const SBufStats& SBuf::GetStats() STUB_RETVAL(SBuf::stats)
SBuf::size_type SBuf::copy(char *, size_type) const STUB_RETVAL(0)
const char* SBuf::rawContent() const STUB_RETVAL(NULL)
char *SBuf::rawAppendStart(size_type) STUB_RETVAL(NULL)
void SBuf::rawAppendFinish(const char *, size_type) STUB
const char* SBuf::c_str() STUB_RETVAL("")
void SBuf::reserveCapacity(size_type) STUB
SBuf::size_type SBuf::reserve(const SBufReservationRequirements &) STUB_RETVAL(0)
SBuf& SBuf::chop(size_type, size_type) STUB_RETVAL(*this)
SBuf& SBuf::trim(const SBuf &, bool, bool) STUB_RETVAL(*this)
SBuf SBuf::substr(size_type, size_type) const STUB_RETVAL(*this)
SBuf::size_type SBuf::find(char, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::find(const SBuf &, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::rfind(char, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::rfind(const SBuf &, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findFirstOf(const CharacterSet &, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findLastOf(const CharacterSet &, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findFirstNotOf(const CharacterSet &, size_type) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findLastNotOf(const CharacterSet &, size_type) const STUB_RETVAL(SBuf::npos)
void SBuf::toLower() STUB
void SBuf::toUpper() STUB

