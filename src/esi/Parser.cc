/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"
#include "esi/Parser.h"
#include "fatal.h"

char *ESIParser::Type = NULL;
ESIParser::Register *ESIParser::Parsers = NULL;
ESIParser::Register *ESIParser::Parser = NULL;

ESIParser::Pointer
ESIParser::NewParser(ESIParserClient *aClient)
{
    if (Parser == NULL) {
        Parser = Parsers;

        while (Parser != NULL && strcasecmp(Parser->name, Type) != 0)
            Parser = Parser->next;

        if (Parser == NULL)
            fatal ("Unknown ESI Parser type");
    }

    return (Parser->newParser)(aClient);
}

ESIParser::Register::Register(const char *_name, ESIParser::Pointer (*_newParser)(ESIParserClient *aClient)) : name(_name), newParser(_newParser)
{
    this->next = ESIParser::Parsers;
    ESIParser::Parsers = this;
}

ESIParser::Register::~Register()
{
    // TODO: support random-order deregistration
    assert(ESIParser::Parsers == this);
    ESIParser::Parsers = next;
}

