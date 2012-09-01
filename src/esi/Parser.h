/*
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
#ifndef SQUID_ESIPARSER_H
#define SQUID_ESIPARSER_H

class ESIParserClient
{
public:
    virtual void start(const char *el, const char **attr, size_t attrCount) = 0;
    virtual void end(const char *el) = 0;
    virtual void parserDefault (const char *s, int len) =0;
    virtual void parserComment (const char *s) = 0;
    virtual ~ESIParserClient() {};
};

/* for RefCountable */
#include "RefCount.h"

class ESIParser : public RefCountable
{
public:
    class Register;
    typedef RefCount<ESIParser> Pointer;

    static void registerParser(const char *name, Pointer (*new_func)(ESIParserClient *aClient));
    static Pointer NewParser(ESIParserClient *aClient);
    static char *Type;

    /**
     \retval true      on success
     \retval false     on what?
     */
    virtual bool parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream) = 0;

    virtual long int lineNumber() const =0;
    virtual char const * errorString() const =0;

protected:
    ESIParser() {};

private:
    static Register *Parser;
    static Register *Parsers;

public:
};

class ESIParser::Register
{

public:
    Register(const char *_name, ESIParser::Pointer (*_newParser)(ESIParserClient *aClient));
    ~Register();

    const char *name;
    ESIParser::Pointer (*newParser)(ESIParserClient *aClient);
    Register * next;
};

#define EsiParserDefinition(ThisClass) \
    ESIParser::Pointer ThisClass::NewParser(ESIParserClient *aClient) \
    { \
	return new ThisClass (aClient); \
    }

#define EsiParserDeclaration \
    static ESIParser::Pointer NewParser(ESIParserClient *aClient)

#endif /* SQUID_ESIPARSER_H */
