/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration Settings */

#ifndef ICMPCONFIG_H
#define ICMPCONFIG_H

/**
 * Squid pinger Configuration settings
 *
 \par
 * This structure is included as a child field of the global Config
 * such that if ICMP is built it can be accessed as Config.pinger.*
 */
class IcmpConfig
{

public:

    /** \todo These methods should really be defined in an ICMPConfig.cc file
     * alongside any custom parsing routines needed for this component.
     * First though, the whole global Config dependancy tree needs fixing */
    IcmpConfig() : program(NULL), enable(0) {};
    ~IcmpConfig() { if (program) delete program; program = NULL; };

    /* variables */

    /** pinger helper application path */
    char *program;

    /** Whether the pinger helper is enabled for use or not */
    /** \todo make this much more memory efficient for a boolean */
    int enable;
};

#endif /* ICMPCONFIG_H */

