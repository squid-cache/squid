/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/AsyncCall.h"
#include "base/AsyncCallList.h"

void
AsyncCallList::add(const AsyncCallPointer &call)
{
    assert(call);
    assert(!call->theNext);
    if (head) { // append
        assert(!tail->theNext);
        tail->theNext = call;
        tail = call;
    } else { // create queue from cratch
        head = tail = call;
    }
    length++;
}

AsyncCallPointer
AsyncCallList::extract()
{
    if (!head)
	    return AsyncCallPointer();
    auto call = head;
    head = call->theNext;
    call->theNext = nullptr;
    if (tail == call)
        tail = nullptr;
    if (length)
        length--;
    return call;
}

