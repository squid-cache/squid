/*
 * $Id$
 *
 * DEBUG: section 3     Configuration Settings
 * AUTHOR: Amos Jeffries
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
 *  This code is copyright (C) 2007 by Treehouse Networks Ltd
 *  of New Zealand. It is published and Lisenced as an extension of
 *  squid under the same conditions as the main squid application.
 */
#ifndef ICMPCONFIG_H
#define ICMPCONFIG_H

#include "config.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

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
