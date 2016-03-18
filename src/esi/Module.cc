/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "esi/CustomParser.h"
#include "esi/Libxml2Parser.h"
#include "esi/Module.h"
/* include for esi/ExpatParser.h must follow esi/Libxml2Parser.h */
/* do not remove this comment, as it acts as barrier for the autmatic sorting */
#include "esi/ExpatParser.h"

static ESIParser::Register *prCustom = 0;
#if HAVE_LIBXML2
static ESIParser::Register *prLibxml = 0;
#endif
#if HAVE_LIBEXPAT
static ESIParser::Register *prExpat = 0;
#endif

void Esi::Init()
{
    assert(!prCustom); // we should be called once

    prCustom = new ESIParser::Register("custom", &ESICustomParser::NewParser);

#if HAVE_LIBXML2
    prLibxml = new ESIParser::Register("libxml2", &ESILibxml2Parser::NewParser);
#endif

#if HAVE_LIBEXPAT
    prExpat = new ESIParser::Register("expat", &ESIExpatParser::NewParser);
#endif
}

void Esi::Clean()
{
    assert(prCustom); // we should be called once, and only after Init()

#if HAVE_LIBEXPAT
    delete prExpat;
    prExpat = NULL;
#endif

#if HAVE_LIBXML2
    delete prLibxml;
    prLibxml = NULL;
#endif

    delete prCustom;
    prCustom = NULL;
}

