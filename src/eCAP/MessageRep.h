
/*
 * $Id$
 */

#ifndef SQUID__ECAP__MESSAGE_REP_H
#define SQUID__ECAP__MESSAGE_REP_H

#include "adaptation/forward.h"
#include <libecap/common/message.h>

namespace Ecap {

// Translates Squid Adaptation::Message into libecap::Message.
class MessageRep: public libecap::Message
{

public:
    MessageRep(Adaptation::Message &aMessage): theMessage(aMessage) {}

private:
    Adaptation::Message &theMessage; // the message being translated to libecap
};

} // namespace Ecap;

#endif /* SQUID__E_CAP__MESSAGE_REP_H */
