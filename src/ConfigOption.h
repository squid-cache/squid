/*
 * $Id: ConfigOption.h,v 1.1 2004/12/20 16:30:32 robertc Exp $
 *
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

#ifndef SQUID_CONFIGOPTION_H
#define SQUID_CONFIGOPTION_H

#include "Array.h"

/* cache option parsers */

class ConfigOption
{

public:
    virtual ~ConfigOption() {}

    virtual bool parse(char const *option, const char *value, int reconfiguring) = 0;
    virtual void dump (StoreEntry * e) const = 0;
};

class ConfigOptionVector : public ConfigOption
{

public:
    virtual ~ConfigOptionVector();
    virtual bool parse(char const *option, const char *value, int reconfiguring);
    virtual void dump(StoreEntry * e) const;
    Vector<ConfigOption *>options;
};

template <class C>

class ConfigOptionAdapter : public ConfigOption
{

public:
    ConfigOptionAdapter (C& theObject, bool (C::*parseFP)(char const *option, const char *value, int reconfiguring), void (C::*dumpFP) (StoreEntry * e) const) : object(theObject), parser (parseFP), dumper(dumpFP) {}

    bool parse(char const *option, const char *value, int reconfiguring)
    {
        if (parser)
            return (object.*parser)(option, value, reconfiguring);

        return false;
    }

    void dump (StoreEntry * e) const
    {
        if (dumper)
            (object.*dumper) (e);
    }

private:
    C &object;
    bool (C::*parser) (char const *option, const char *value, int reconfiguring) ;
    void (C::*dumper)(StoreEntry * e) const;
};

#endif /* SQUID_CONFIGOPTION_H */
