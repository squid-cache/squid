/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
class DelayedAsyncCalls;
class Raw;
class RegexPattern;
class ScopedId;
class Stopwatch;

template<class Cbc> class CbcPointer;
template<class RefCountableKid> class RefCount;
template<class Job> class JobWait;
template<class Answer> class AsyncCallback;

typedef CbcPointer<AsyncJob> AsyncJobPointer;
typedef RefCount<CodeContext> CodeContextPointer;
using AsyncCallPointer = RefCount<AsyncCall>;

#endif /* SQUID_SRC_BASE_FORWARD_H */

