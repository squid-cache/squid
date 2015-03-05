/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_PACKABLE_H
#define SQUID_SRC_BASE_PACKABLE_H

/**
 * A uniform interface to store-like modules
 *
 * Rationale:
 * ----------
 *
 * We have two major interfaces Comm and Store, which take a variety of
 * different data buffering objects and have different output actions
 * to be performed on data.
 *
 * Store has a nice storeAppend[Printf] capability which makes "storing"
 * things easy and painless.
 *
 * Comm lacks commAppend[Printf] because Comm does not handle its own
 * buffers (no mem_obj equivalent for Comm).
 *
 * Thus, if one wants to be able to Store _and_ Comm::Write an object, 'e
 * has to implement almost identical functions for using all the data
 * storage objects and their associated actions. Doing this for all the
 * available data storage types is a tedious nightmare of almost-duplicated
 * code.
 *
 * Packer
 * ------
 *
 * Objects inheriting from Packable provide a uniform interface for code to
 * assemble data before passing to Store and Comm modules.
 *
 * Packable objects have their own append and printf routines that "know"
 * where to send incoming data. In case of Store interface, sending data to
 * storeAppend. Packable buffer objects retain the data such that it can be
 * flushed later to Comm::Write.
 *
 * Thus, one can write just one function that will take a Packer* pointer
 * and either "pack" things for Comm::Write or "append" things to Store,
 * depending on actual Packable object supplied.
 */
class Packable
{
public:
    /// Appends a c-string to existing packed data.
    virtual void append(const char *buf, int size) = 0;

    /// Append operation with printf-style arguments.
    void appendf(const char *fmt,...) PRINTF_FORMAT_ARG2
    {
        va_list args;
        va_start(args, fmt);
        vappendf(fmt, args);
        va_end(args);
    }
#if 0
    /*
     * \note  we use Printf instead of printf so the compiler won't
     *        think we're calling the libc printf()
     */
    void Printf(const char *fmt,...) PRINTF_FORMAT_ARG2
    {
        va_list args;
        va_start(args, fmt);
        vappendf(fmt, args);
        va_end(args);
    }
#endif

    /** Append operation, with vsprintf(3)-style arguments.
     *
     * \note arguments may be evaluated more than once, be careful
     *       of side-effects
     */
    virtual void vappendf(const char *fmt, va_list ap) = 0;
};

#endif /* SQUID_SRC_BASE_PACKABLE_H */

