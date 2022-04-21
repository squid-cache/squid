/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_FORWARD_H
#define SQUID_SRC_BASE_FORWARD_H

class AsyncCall;
class AsyncCallQueue;
class AsyncJob;
class CallDialer;
class CodeContext;
class ScopedId;
class BadOptionalAccess;
class Raw;
class RegexPattern;

template <typename Value> class Optional;

template<class Cbc> class CbcPointer;
template<class RefCountableKid> class RefCount;
template<class Job> class JobWait;

typedef CbcPointer<AsyncJob> AsyncJobPointer;
typedef RefCount<CodeContext> CodeContextPointer;
typedef RefCount <AsyncCall> AsyncCallPointer;

#endif /* SQUID_SRC_BASE_FORWARD_H */

