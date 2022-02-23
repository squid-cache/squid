/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "ipc/RequestId.h"

#include <iostream>

Ipc::RequestId::RequestId(const Index anIndex):
    qid_(anIndex ? MyQuestionerId() : QuestionerId()),
    index_(anIndex)
{
}

std::ostream &
Ipc::operator <<(std::ostream &os, const RequestId &requestId)
{
    os << requestId.index() << '@' << requestId.questioner();
    return os;
}

