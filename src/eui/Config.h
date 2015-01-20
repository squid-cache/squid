/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EUI_CONFIG_H
#define SQUID_EUI_CONFIG_H

namespace Eui
{

class EuiConfig
{
public:
    int euiLookup;
};

extern EuiConfig TheConfig;

} // namespace Eui

#endif /* SQUID_EUI_CONFIG_H */

