/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SBUF_FORWARD_H
#define SQUID_SRC_SBUF_FORWARD_H

#include <functional>
#include <list>

class MemBlob;

class SBuf;
class SBufIterator;
class SBufReverseIterator;
class SBufReservationRequirements;

class OutOfBoundsException;
class InvalidParamException;
class SBufTooBigException;

class SBufStats;
typedef std::list<SBuf> SBufList;

class SBufEqual;
class SBufStartsWith;
class SBufAddLength;
namespace std {
template <> struct hash<SBuf>;
}
class CaseInsensitiveSBufHash;

#endif /* SQUID_SRC_SBUF_FORWARD_H */

