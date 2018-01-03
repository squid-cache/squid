/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HELPER_CHILDCONFIG_H
#define _SQUID_SRC_HELPER_CHILDCONFIG_H

namespace Helper
{

/**
 * Contains statistics of a particular type of child helper.
 *
 * Some derived from a helper children configuration option,
 * some from runtime stats on the currently active children.
 */
class ChildConfig
{
public:
    ChildConfig();
    explicit ChildConfig(const unsigned int m);

    /**
     * When new helpers are needed call this to find out how many more
     * we are allowed to start.
     * \retval 0       No more helpers may be started right now.
     * \retval N < 0   Error. No more helpers may be started.
     * \retval N       N more helpers may be started immediately.
     */
    int needNew() const;
    void parseConfig();

    /**
     * Update an existing set of details with new start/max/idle/concurrent limits.
     * This is for parsing new child settings into an object incrementally then updating
     * the running set without loosing any of the active state or causing races.
     */
    ChildConfig &updateLimits(const ChildConfig &rhs);

    /* values from squid.conf */
public:

    /** maximum child process limits. How many of this helper the system can cope with */
    unsigned int n_max;

    /**
     * Number of children to kick off at startup.
     * set via the startup=N option.
     *
     * By default if undefined 1 will be started immediately for use.
     * The minimum/idle amount will be scheduled for starting as soon as possible after startup is completed.
     */
    unsigned int n_startup;

    /**
     * Number of helper children to keep available as a buffer against sudden bursts of requests.
     * set via the idle=N option. May be zero.
     *
     * The default value for backward compatibility the default for this is the same as maximum children.
     * For now the actual number of idle children is only reduced by a reconfigure operation. This may change.
     */
    unsigned int n_idle;

    /**
     * How many concurrent requests each child helper may be capable of handling.
     * Default: 0  - no concurrency possible.
     */
    unsigned int concurrency;

    /* derived from active operations */

    /**
     * Total helper children objects currently existing.
     * Produced as a side effect of starting children or their stopping.
     */
    unsigned int n_running;

    /**
     * Count of helper children active (not shutting down).
     * This includes both idle and in-use children.
     */
    unsigned int n_active;

    /**
     * The requests queue size. By default it is of size 2*n_max
     */
    unsigned int queue_size;

    /// how to handle a serious problem with a helper request submission
    enum SubmissionErrorHandlingAction {
        actDie, ///< kill the caller process (i.e., Squid worker)
        actErr  ///< drop the request and send an error to the caller
    };
    /// how to handle a new request for helper that was overloaded for too long
    SubmissionErrorHandlingAction onPersistentOverload;

    /**
     * True if the default queue size is used.
     * Needed in the cases where we need to adjust default queue_size in
     * special configurations, for example when redirector_bypass is used.
     */
    bool defaultQueueSize;
};

} // namespace Helper

/* Legacy parser interface */
#define parse_HelperChildConfig(c)     (c)->parseConfig()
#define dump_HelperChildConfig(e,n,c)  storeAppendPrintf((e), "\n%s %d startup=%d idle=%d concurrency=%d\n", (n), (c).n_max, (c).n_startup, (c).n_idle, (c).concurrency)
#define free_HelperChildConfig(dummy)  // NO.

#endif /* _SQUID_SRC_HELPER_CHILDCONFIG_H */

