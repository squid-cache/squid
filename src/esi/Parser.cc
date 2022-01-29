/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"
#include "Debug.h"
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
    if (!Parser) {
        // if esi_parser is configured, use that
        const char *selectParserName = Type;
        if (!selectParserName || strcasecmp(selectParserName, "auto") == 0) {
#if HAVE_LIBXML2
            // libxml2 is the more secure. prefer when possible
            selectParserName = "libxml2";
#else
            // expat is more widely available
            selectParserName = "expat";
#endif
        }

        for (auto *p : GetRegistry()) {
            if (p && strcasecmp(p->name, selectParserName) == 0)
                Parser = p;
        }

        if (!Parser)
            fatalf("Unknown ESI Parser type '%s'", selectParserName);
        debugs(86, 2, "selected ESI parser: " << Parser->name);
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

