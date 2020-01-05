/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_FORWARD_H
#define SQUID_SRC_BASE_FORWARD_H

class AsyncCallQueue;
class AsyncJob;
class CallDialer;
class CodeContext;
class ScopedId;

template<class Cbc> class CbcPointer;
template<class RefCountableKid> class RefCount;

typedef CbcPointer<AsyncJob> AsyncJobPointer;
typedef RefCount<CodeContext> CodeContextPointer;

#endif /* SQUID_SRC_BASE_FORWARD_H */

