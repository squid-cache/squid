/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_REQUESTID_H
#define SQUID_IPC_REQUESTID_H

#include "ipc/forward.h"
#include "ipc/QuestionerId.h"

#include <iosfwd>

namespace Ipc
{

/// uniquely identifies an IPC request among same-type concurrent IPC requests
/// submitted by a single Squid instance
class RequestId
{
public:
    /// A simple ID for correlating IPC responses with pending requests.
    /// Value 0 has a special meaning of "unset/unknown", but otherwise opaque.
    typedef unsigned int Index;

    /// Request sender's constructor.
    /// For performance and clarity sake, default constructor is preferred to 0 index.
    explicit RequestId(Index);

    /// request recipient's constructor
    RequestId() = default;

    /// Make the ID unset/unknown.
    /// Optimization: leaves the questioner field alone.
    void reset() { index_ = 0; }

    /// Make the ID set/known with the given (by the questioner) index.
    /// For performance and clarity sake, reset(void) is preferred to reset(0).
    void reset(const Index anIndex) { *this = RequestId(anIndex); }

    QuestionerId questioner() const { return qid_; }
    Index index() const { return index_; }

    // these conversion operators allow our users to treat us as an Index
    operator Index() const { return index_; }
    RequestId &operator =(const Index anIndex) { anIndex ? reset(anIndex) : reset(); return *this; }

private:
    /// the sender of the request
    QuestionerId qid_;

    /// request ID; unique within pending same-qid_ questions of the same kind
    Index index_ = 0;
};

std::ostream &operator <<(std::ostream &, const RequestId &);

} // namespace Ipc;

#endif /* SQUID_IPC_REQUESTID_H */

