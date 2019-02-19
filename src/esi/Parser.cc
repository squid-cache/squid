/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
ESIParser::Register *ESIParser::Parser = NULL;

std::list<ESIParser::Register *> &
ESIParser::GetRegistry()
{
    static std::list<ESIParser::Register *> parsers;
    return parsers;
}

ESIParser::Pointer
ESIParser::NewParser(ESIParserClient *aClient)
{
    if (Parser == NULL) {
        Parser = GetRegistry().front();

        // if type name matters, use it
        if (strcasecmp(Type, "auto") != 0) {
            for (auto *p : GetRegistry()) {
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
    ESIParser::GetRegistry().emplace_back(this);
}

ESIParser::Register::~Register()
{
    ESIParser::GetRegistry().remove(this);
}

