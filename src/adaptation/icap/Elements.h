
/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
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
