/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__ANSWER_H
#define SQUID_ADAPTATION__ANSWER_H

#include "adaptation/forward.h"
#include "HttpMsg.h"

#include <iosfwd>

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
    static Answer Forward(HttpMsg *aMsg); ///< create an akForward answer
    static Answer Block(const String &aRule); ///< create an akBlock answer

    std::ostream &print(std::ostream &os) const;

public:
    HttpMsg::Pointer message; ///< HTTP request or response to forward
    String ruleId; ///< ACL (or similar rule) name that blocked forwarding
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

#endif /* SQUID_ADAPTATION__ANSWER_H */

