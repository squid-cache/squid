/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IPC_QUESTIONERID_H
#define SQUID_SRC_IPC_QUESTIONERID_H

#include "ipc/forward.h"

#include <iosfwd>

namespace Ipc
{

/// Identifies a kid process sending IPC messages that require an answer.
/// Must be unique across all kids with pending questions.
class QuestionerId
{
public:
    /// to-be-determined ID
    QuestionerId() = default;

    /// for sending the ID of the asking process
    void pack(TypedMsgHdr &) const;

    /// for receiving the ID of the asking process
    void unpack(const TypedMsgHdr &);

    /// does nothing but throws if the questioner was not the current process
    void rejectAnswerIfStale() const;

    /// reports the stored opaque ID value (for debugging)
    void print(std::ostream &) const;

private:
    /// for MyQuestionerId() convenience
    explicit QuestionerId(const pid_t aPid): pid(aPid) {}
    friend QuestionerId MyQuestionerId();

    /// OS process ID of the asking kid. If the kid restarts, it is assumed
    /// not to wrap back to the old value until the answer is received.
    pid_t pid = -1;
};

/// the questioner ID of the current/calling process
QuestionerId MyQuestionerId();

/// Convenience wrapper for rejecting (freshly parsed) stale answers.
/// All answers are assumed to have a "QuestionerId intendedRecepient()" member.
template <class Answer>
const Answer &
Mine(const Answer &answer)
{
    answer.intendedRecepient().rejectAnswerIfStale();
    return answer;
}

inline std::ostream &
operator <<(std::ostream &os, const QuestionerId &qid)
{
    qid.print(os);
    return os;
}

} // namespace Ipc;

#endif /* SQUID_SRC_IPC_QUESTIONERID_H */

