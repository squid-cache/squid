/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Assure.h"
#include "base/AsyncCall.h"
#include "base/AsyncCallList.h"

void
AsyncCallList::add(const AsyncCall::Pointer &call)
{
    Assure(call);
    Assure(!call->Next());
    if (tail) { // append to the existing list
        Assure(head);
        Assure(!tail->Next());
        tail->setNext(call);
        tail = call;
    } else { // create a list from scratch
        Assure(!head);
        head = tail = call;
    }
    ++length;
    Assure(length); // no overflows
}

AsyncCall::Pointer
AsyncCallList::extract()
{
    if (!head)
        return AsyncCallPointer();

    Assure(tail);
    Assure(length);
    const auto call = head;
    head = call->Next();
    call->setNext(nullptr);
    if (tail == call)
        tail = nullptr;
    --length;
    return call;
}

