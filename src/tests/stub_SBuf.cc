/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/DetailedStats.h"

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
SBuf::SBuf(const SBuf &S) {}
SBuf::SBuf(const char *S, size_type n) {}
SBuf::SBuf(const char *S) {}
SBuf::SBuf(const std::string &s) {}
SBuf::~SBuf() {}
SBuf& SBuf::assign(const SBuf &S) STUB_RETVAL(*this)
SBuf& SBuf::assign(const char *S, size_type n) STUB_RETVAL(*this)
void clear() STUB
SBuf& SBuf::append(const SBuf & S) STUB_RETVAL(*this)
SBuf& SBuf::append(const char * S, size_type Ssize) STUB_RETVAL(*this)
SBuf& Printf(const char *fmt, ...);
SBuf& SBuf::appendf(const char *fmt, ...) STUB_RETVAL(*this)
SBuf& SBuf::vappendf(const char *fmt, va_list vargs) STUB_RETVAL(*this)
std::ostream& SBuf::print(std::ostream &os) const STUB_RETVAL(os)
std::ostream& SBuf::dump(std::ostream &os) const STUB_RETVAL(os)
void SBuf::setAt(size_type pos, char toset) STUB
int SBuf::compare(const SBuf &S, const SBufCaseSensitive isCaseSensitive, const size_type n) const STUB_RETVAL(-1)
int SBuf::compare(const char *s, const SBufCaseSensitive isCaseSensitive, const size_type n) const STUB_RETVAL(-1)
bool SBuf::startsWith(const SBuf &S, const SBufCaseSensitive isCaseSensitive) const STUB_RETVAL(false)
bool SBuf::operator ==(const SBuf & S) const STUB_RETVAL(false)
bool SBuf::operator !=(const SBuf & S) const STUB_RETVAL(false)
SBuf SBuf::consume(size_type n) STUB_RETVAL(*this)
const SBufStats& SBuf::GetStats() STUB_RETVAL(SBuf::stats)
SBuf::size_type SBuf::copy(char *dest, size_type n) const STUB_RETVAL(0)
const char* SBuf::rawContent() const STUB_RETVAL(NULL)
char *SBuf::rawAppendStart(size_type) STUB_RETVAL(NULL)
void SBuf::rawAppendFinish(const char *, size_type) STUB
const char* SBuf::c_str() STUB_RETVAL("")
void SBuf::reserveCapacity(size_type minCapacity) STUB
SBuf::size_type SBuf::reserve(const SBufReservationRequirements &) STUB_RETVAL(0)
SBuf& SBuf::chop(size_type pos, size_type n) STUB_RETVAL(*this)
SBuf& SBuf::trim(const SBuf &toRemove, bool atBeginning, bool atEnd) STUB_RETVAL(*this)
SBuf SBuf::substr(size_type pos, size_type n) const STUB_RETVAL(*this)
SBuf::size_type SBuf::find(char c, size_type startPos) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::find(const SBuf & str, size_type startPos) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::rfind(char c, size_type endPos) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::rfind(const SBuf &str, size_type endPos) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findFirstOf(const CharacterSet &set, size_type startPos) const STUB_RETVAL(SBuf::npos)
SBuf::size_type SBuf::findFirstNotOf(const CharacterSet &set, size_type startPos) const STUB_RETVAL(SBuf::npos)
void SBuf::toLower() STUB
void SBuf::toUpper() STUB

