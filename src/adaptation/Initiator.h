#ifndef SQUID_ADAPTATION__INITIATOR_H
#define SQUID_ADAPTATION__INITIATOR_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "adaptation/forward.h"
#include "HttpMsg.h"

#include <iosfwd>

/*
 * The ICAP Initiator is an ICAP vectoring point that initates ICAP
 * transactions. This interface exists to allow ICAP transactions to
 * signal their initiators that they have the answer from the ICAP server
 * or that the ICAP query has aborted and there will be no answer. It
 * is also handy for implementing common initiator actions such as starting
 * or aborting an ICAP transaction.
 */

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
    HttpMsgPointerT<HttpMsg> message; ///< HTTP request or response to forward
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

class Initiator: virtual public AsyncJob
{
public:
    Initiator(): AsyncJob("Initiator") {}
    virtual ~Initiator() {}

    /// called with the initial adaptation decision (adapt, block, error);
    /// virgin and/or adapted body transmission may continue after this
    virtual void noteAdaptationAnswer(const Answer &answer) = 0;

protected:
    ///< starts freshly created initiate and returns a safe pointer to it
    CbcPointer<Initiate> initiateAdaptation(Initiate *x);

    /// clears the pointer (does not call announceInitiatorAbort)
    void clearAdaptation(CbcPointer<Initiate> &x);

    /// inform the transaction about abnormal termination and clear the pointer
    void announceInitiatorAbort(CbcPointer<Initiate> &x);

    /// Must(initiated(initiate)) instead of Must(initiate.set()), for clarity
    bool initiated(const CbcPointer<AsyncJob> &job) const { return job.set(); }
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__INITIATOR_H */
