/*
 * $Id$
 *
 * DEBUG: section 03    Configuration File Parsing
 * AUTHOR: Robert Collins
 *
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

#include "squid.h"
#include "ConfigOption.h"

ConfigOptionVector::~ConfigOptionVector()
{
    while (options.size()) {
        delete options.back();
        options.pop_back();
    }
}

bool
ConfigOptionVector::parse(char const *option, const char *value, int isaReconfig)
{
    Vector<ConfigOption *>::iterator i = options.begin();

    while (i != options.end()) {
        if ((*i)->parse(option,value, isaReconfig))
            return true;

        ++i;
    }

    return false;
}

void
ConfigOptionVector::dump(StoreEntry * e) const
{
    for (Vector<ConfigOption *>::const_iterator i = options.begin();
            i != options.end(); ++i)
        (*i)->dump(e);
}
