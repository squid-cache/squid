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
AsyncCallList::add(const AsyncCall::Pointer &call)
{
    assert(call);
    assert(!call->Next());
    if (head) { // append
        assert(!tail->Next());
        tail->setNext(call);
        tail = call;
    } else { // create a list from scratch
        head = tail = call;
    }
    length++;
}

AsyncCall::Pointer
AsyncCallList::extract()
{
    if (!head)
	    return AsyncCallPointer();

    auto call = head;
    head = call->Next();
    call->setNext(nullptr);
    if (tail == call)
        tail = nullptr;
    if (length)
        length--;
    return call;
}

