/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_ANSWER_H
#define SQUID_SRC_ADAPTATION_ANSWER_H

#include "acl/Acl.h"
#include "adaptation/forward.h"
#include "http/forward.h"
#include "sbuf/SBuf.h"

#include <iosfwd>
#include <optional>

namespace Adaptation
{

/// summarizes adaptation service answer for the noteAdaptationAnswer() API
class Answer
{
public:
    /// helps interpret other members without a class hierarchy
    typedef enum {
        akForward, ///< forward the supplied adapted HTTP message
        akBlock, ///< block or deny the master xaction; see authority
        akError, ///< no adapted message will come; see bypassable
    } Kind;

    static Answer Error(bool final); ///< create an akError answer
    static Answer Forward(Http::Message *aMsg); ///< create an akForward answer
    static Answer Block(const SBuf &aRule); ///< create an akBlock answer

    /// creates an Acl::Answer from akBlock answer
    Acl::Answer blockedToChecklistAnswer() const;

    std::ostream &print(std::ostream &os) const;

public:
    Http::MessagePointer message; ///< HTTP request or response to forward
    std::optional<SBuf> ruleId; ///< ACL (or similar rule) name that blocked forwarding
    bool final; ///< whether the error, if any, cannot be bypassed
    Kind kind; ///< the type of the answer

private:
    explicit Answer(Kind aKind); ///< use static creators instead
};

inline
std::ostream &operator <<(std::ostream &os, const Answer &answer)
{
    return answer.print(os);
}

} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ANSWER_H */

