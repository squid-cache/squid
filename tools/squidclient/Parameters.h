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

/// global squidcleint parameters
extern Parameters scParams;

#endif /* _SQUID_TOOLS_SQUIDCLIENT_PARAMETERS_H */
