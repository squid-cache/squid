/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_TOOLS_CLIENT_PING_H
#define _SQUID_TOOLS_CLIENT_PING_H

/**
 * API for looping the squidclient request message
 * repeatedly.
 */
namespace Ping
{

/// parameters controlling 'ping' mode message looping.
class TheConfig
{
public:
    TheConfig() : enable(false), count(0), interval(1*1000) {}

    /// display Ping Options command line help to stderr
    void usage();

    /**
     * parse --ping command line options
     * \return true if there are other options still to parse
     */
    bool parseCommandOpts(int argc, char *argv[], int c, int &optIndex);

    bool enable;
    int count;
    int interval;
};

extern TheConfig Config;

/// initialize the squidclient ping mode
uint32_t Init();

/// whether ping loop is completed at the given iteration.
inline bool LoopDone(int i)
{
    return !Ping::Config.enable || (Ping::Config.count && i >= Ping::Config.count);
}

/// start timing a new transaction
void TimerStart();

/// calculate and display the statistics for a complete transaction
/// \param fsize number of bytes transferred during this transaction (for KB/s measure)
void TimerStop(size_t fsize);

/// display summary of ping data collected
void DisplayStats();

} // namespace Ping

#endif /* _SQUID_TOOLS_CLIENT_PING_H */

