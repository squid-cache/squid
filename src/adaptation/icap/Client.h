/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_ICAP_CLIENT_H
#define SQUID_SRC_ADAPTATION_ICAP_CLIENT_H

// ICAP-related things needed by code unaware of ICAP internals.

namespace Adaptation
{
namespace Icap
{

void InitModule();
void CleanModule();

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ICAP_CLIENT_H */

