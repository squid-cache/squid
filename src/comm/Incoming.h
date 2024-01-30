/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_COMM_INCOMING_H
#define SQUID_SRC_COMM_INCOMING_H

#if USE_POLL || USE_SELECT

#include "SquidConfig.h"
#include "StatHist.h"

namespace Comm
{

/**
 * Automatic tuning for incoming requests.
 *
 * INCOMING sockets are the listening ports for transport protocols.
 * We need to check these fairly regularly, but how often?  When the
 * load increases, we want to check the incoming sockets more often.
 * If we have a lot of one protocol incoming, then we need to check
 * those sockets more than others.
 *
 * \copydoc Comm::Incoming::check()
 *
 * \copydoc Comm::Incoming::finishPolling()
 *
 * Caveats:
 *
 *   \copydoc Comm::Incoming::Factor
 *
 *   \copydoc Comm::Incoming::MaxInterval
 */
class Incoming
{
public:
#if !defined(INCOMING_FACTOR)
#define INCOMING_FACTOR 5
#endif
    /**
     * The higher the INCOMING_FACTOR, the slower the algorithm will
     * respond to load spikes/increases/decreases in demand. A value
     * between 3 and 8 is recommended.
     */
    static const int Factor = INCOMING_FACTOR;

    /**
     * Magic upper limit on interval.
     * At the largest value the cache will effectively be idling.
     */
    static const int MaxInterval = (256 << Factor);

    // TODO replace with constructor initialization
    void init(int n) { nMaximum = n; history.enumInit(n); }

    /**
     * Preparation for polling incoming sockets.
     *
     * \param n  the number of relevant listening FDs currently open.
     *
     * \return whether it is possible to check with poll(2)/select(2).
     */
    bool startPolling(int n) { ioEvents = 0; return (n > 0); }

    /**
     * Finalize and update records when incoming sockets polled.
     *
     * The new interval is calculated as the current interval,
     * plus what we would like to see as an average number of events,
     * minus the number of events just processed.
     */
    void finishPolling(int, SquidConfig::CommIncoming::Measure &);

    /**
     * Every time we check incoming sockets, we count how many new
     * messages or connections were processed.  This is used to adjust
     * the interval for the next iteration.
     *
     * \return whether it is time to check incoming sockets.
     */
    bool check() { return (++ioEvents > (interval >> Factor)); }

    /*
     * How many normal I/O events to process before checking
     * incoming sockets again.
     *
     * \note We store the interval multiplied by a factor of
     *       (2^Factor) to have some pseudo-floating
     *       point precision.
     */
    int interval = (16 << Factor);

    /** History of I/O events timing on listening ports.
     *
     * You can see the current values of the interval's,
     * as well as histograms of 'incoming_events' in the cache
     * manager 'comm_*_incoming' reports.
     */
    StatHist history;

private:
    /**
     * Count of normal I/O events processed since last call to
     * startPolling().  When ioEvents > interval, it is time to
     * check incoming sockets again.
     */
    int ioEvents = 0;

    /**
     * Maximum value to record for number of I/O events within
     * an interval. Set using init(N).
     */
    int nMaximum = 0;
};

} // namespace Comm

#endif /* USE_POLL || USE_SELECT */
#endif /* SQUID_SRC_COMM_INCOMING_H */
