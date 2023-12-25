/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPELEMENTS_H
#define SQUID_ICAPELEMENTS_H

#include "adaptation/Elements.h"

// ICAP-related things shared by many ICAP classes

namespace Adaptation
{
namespace Icap
{

//TODO: remove the ICAP namespace
namespace ICAP
{
using Adaptation::Method;
using Adaptation::methodNone;
using Adaptation::methodRespmod;
using Adaptation::methodReqmod;

using Adaptation::VectPoint;
using Adaptation::pointNone;
using Adaptation::pointPreCache;
using Adaptation::pointPostCache;

using Adaptation::crlf;
using Adaptation::methodStr;
using Adaptation::vectPointStr;
}

typedef const char *XactOutcome; ///< transaction result for logging
extern const XactOutcome xoUnknown; ///< initial value: outcome was not set
extern const XactOutcome xoGone; ///< initiator gone, will not continue
extern const XactOutcome xoRace; ///< ICAP server closed pconn when we started
extern const XactOutcome xoError; ///< all kinds of transaction errors
extern const XactOutcome xoOpt; ///< OPTION transaction
extern const XactOutcome xoEcho; ///< preserved virgin message (ICAP 204)
extern const XactOutcome xoPartEcho; ///< preserved virgin msg part (ICAP 206)
extern const XactOutcome xoModified; ///< replaced virgin msg with adapted
extern const XactOutcome xoSatisfied; ///< request satisfaction

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPCLIENT_H */

