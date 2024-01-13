/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_FORWARD_H
#define SQUID_SRC_BASE_FORWARD_H

#include "async/forward.h" // XXX: remove before shipping

class CodeContext;
class Raw;
class RegexPattern;
class ScopedId;
class Stopwatch;

template<class Cbc> class CbcPointer;
template<class RefCountableKid> class RefCount;

typedef CbcPointer<AsyncJob> AsyncJobPointer;
typedef RefCount<CodeContext> CodeContextPointer;

#endif /* SQUID_SRC_BASE_FORWARD_H */

