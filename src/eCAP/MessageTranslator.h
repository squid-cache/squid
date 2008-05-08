
/*
 * $Id$
 */

#ifndef SQUID__ECAP__MESSAGE_TRANSLATOR_H
#define SQUID__ECAP__MESSAGE_TRANSLATOR_H

#include "adaptation/forward.h"
#include <libecap/common/message.h>

namespace Ecap {

// Translates Squid Adaptation::Message into libecap::Message.
class MessageTranslator: public libecap::Message
{

public:
    MessageTranslator(Adaptation::Message &aMessage): theMessage(aMessage) {}

private:
    Adaptation::Message &theMessage; // the message being translated to libecap
};

} // namespace Ecap;

#endif /* SQUID__E_CAP__MESSAGE_TRANSLATOR_H */
