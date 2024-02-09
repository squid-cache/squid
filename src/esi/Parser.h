/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ESI_PARSER_H
#define SQUID_SRC_ESI_PARSER_H

#include "base/RefCount.h"

#include <list>

class ESIParserClient
{
public:
    virtual void start(const char *el, const char **attr, size_t attrCount) = 0;
    virtual void end(const char *el) = 0;
    virtual void parserDefault (const char *s, int len) =0;
    virtual void parserComment (const char *s) = 0;
    virtual ~ESIParserClient() {};
};

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
    static std::list<Register *> & GetRegistry();
};

class ESIParser::Register
{

public:
    Register(const char *_name, ESIParser::Pointer (*_newParser)(ESIParserClient *aClient));
    ~Register();

    const char *name;
    ESIParser::Pointer (*newParser)(ESIParserClient *aClient);
};

#define EsiParserDefinition(ThisClass) \
    ESIParser::Pointer ThisClass::NewParser(ESIParserClient *aClient) \
    { \
    return new ThisClass (aClient); \
    }

#define EsiParserDeclaration \
    static ESIParser::Pointer NewParser(ESIParserClient *aClient)

#endif /* SQUID_SRC_ESI_PARSER_H */

