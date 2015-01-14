/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_TOOLS_SQUIDCLIENT_PARAMETERS_H
#define _SQUID_TOOLS_SQUIDCLIENT_PARAMETERS_H

/**
 * squidclient command line parameters.
 */
class Parameters
{
public:
    Parameters() : verbosityLevel(0) {}

    /**
     * What verbosity level to display.
     *
     *  0  : display no debug traces
     *  1  : display outgoing request message
     *  2+ : display all actions taken
     */
    int verbosityLevel;
};

/// display debug messages at varying verbosity levels
#define debugVerbose(LEVEL, MESSAGE) \
    while ((LEVEL) <= scParams.verbosityLevel) {std::cerr << MESSAGE << std::endl; break;}

/// global squidcleint parameters
extern Parameters scParams;

#endif /* _SQUID_TOOLS_SQUIDCLIENT_PARAMETERS_H */

