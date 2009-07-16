#include "squid.h"
#include "adaptation/icap/Elements.h"

// TODO: remove this file?
namespace Adaptation {
namespace Icap {

const XactOutcome xoUnknown = "ICAP_ERR_UNKNOWN";
const XactOutcome xoError = "ICAP_ERR_OTHER";
const XactOutcome xoOpt = "ICAP_OPT";
const XactOutcome xoEcho = "ICAP_ECHO";
const XactOutcome xoModified = "ICAP_MOD";
const XactOutcome xoSatisfied = "ICAP_SAT";

} // namespace Icap
} // namespace Adaptation
