#ifndef SQUID_YESNONONE_H_
#define SQUID_YESNONONE_H_
/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 */

/// Used for boolean enabled/disabled options with complex default logic.
/// Allows Squid to compute the right default after configuration.
/// Checks that not-yet-defined option values are not used.
class YesNoNone
{
// TODO: generalize to non-boolean option types
public:
    YesNoNone(): option(0) {}

    /// returns true iff enabled; asserts if the option has not been configured
    operator void *() const; // TODO: use a fancy/safer version of the operator

    /// enables or disables the option;
    void configure(bool beSet);

    /// whether the option was enabled or disabled, by user or Squid
    bool configured() const { return option != 0; }

private:
    enum { optUnspecified = -1, optDisabled = 0, optEnabled = 1 };
    int option; ///< configured value or zero
};

#endif /* SQUID_YESNONONE_H_ */
