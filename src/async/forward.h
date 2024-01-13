/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ASYNC_FORWARD_H
#define SQUID_SRC_ASYNC_FORWARD_H

template<class RefCountableKid> class RefCount; //XXX: duplicate from base/forward.h

class AsyncCall;
class AsyncCallQueue;
class AsyncJob;
class DelayedAsyncCalls;

template <class Answer> class AsyncCallback;
using AsyncCallPointer = RefCount<AsyncCall>;

#endif /* SQUID_SRC_ASYNC_FORWARD_H */
