/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CONFIGOPTION_H
#define SQUID_CONFIGOPTION_H

#include <vector>

class StoreEntry;

/* cache option parsers */

class ConfigOption
{

public:
    virtual ~ConfigOption() {}

    virtual bool parse(char const *option, const char *value, int reconfiguring) = 0;
    virtual void dump(StoreEntry * e) const = 0;
};

class ConfigOptionVector : public ConfigOption
{

public:
    virtual ~ConfigOptionVector();
    virtual bool parse(char const *option, const char *value, int reconfiguring);
    virtual void dump(StoreEntry * e) const;
    std::vector<ConfigOption *>options;
};

template <class C>
class ConfigOptionAdapter : public ConfigOption
{

public:
    ConfigOptionAdapter(C& theObject, bool (C::*parseFP)(char const *option, const char *value, int reconfiguring), void (C::*dumpFP)(StoreEntry * e) const) : object(theObject), parser(parseFP), dumper(dumpFP) {}

    bool parse(char const *option, const char *value, int isaReconf) {
        if (parser)
            return (object.*parser)(option, value, isaReconf);

        return false;
    }

    void dump(StoreEntry * e) const {
        if (dumper)
            (object.*dumper)(e);
    }

private:
    C &object;
    bool (C::*parser)(char const *option, const char *value, int reconfiguring) ;
    void (C::*dumper)(StoreEntry * e) const;
};

#endif /* SQUID_CONFIGOPTION_H */

