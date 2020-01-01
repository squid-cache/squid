/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPCLIENT_H
#define SQUID_ICAPCLIENT_H

// ICAP-related things needed by code unaware of ICAP internals.

namespace Adaptation
{
namespace Icap
{

void InitModule();
void CleanModule();

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPCLIENT_H */

