/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/Elements.h"

// TODO: remove this file?
namespace Adaptation
{
namespace Icap
{

const XactOutcome xoUnknown = "ICAP_ERR_UNKNOWN";
const XactOutcome xoGone = "ICAP_ERR_GONE";
const XactOutcome xoRace = "ICAP_ERR_RACE";
const XactOutcome xoError = "ICAP_ERR_OTHER";
const XactOutcome xoOpt = "ICAP_OPT";
const XactOutcome xoEcho = "ICAP_ECHO";
const XactOutcome xoPartEcho = "ICAP_PART_ECHO";
const XactOutcome xoModified = "ICAP_MOD";
const XactOutcome xoSatisfied = "ICAP_SAT";

} // namespace Icap
} // namespace Adaptation

