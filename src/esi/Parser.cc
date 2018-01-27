/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
std::list<ESIParser::Register *> ESIParser::Parsers;
ESIParser::Register *ESIParser::Parser = NULL;

ESIParser::Pointer
ESIParser::NewParser(ESIParserClient *aClient)
{
    if (Parser == NULL) {
        Parser = Parsers.front();

        // if type name matters, use it
        if (strcasecmp(Type, "auto") != 0) {
            for (auto *p : Parsers) {
                if (p && strcasecmp(p->name, Type) != 0)
                    Parser = p;
            }
        }

        if (Parser == NULL)
            fatal ("Unknown ESI Parser type");
    }

    return (Parser->newParser)(aClient);
}

ESIParser::Register::Register(const char *_name, ESIParser::Pointer (*_newParser)(ESIParserClient *aClient)) : name(_name), newParser(_newParser)
{
    ESIParser::Parsers.emplace_back(this);
}

ESIParser::Register::~Register()
{
    ESIParser::Parsers.remove(this);
}

