/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "esi/Libxml2Parser.h"
#include "esi/Module.h"
/* include for esi/ExpatParser.h must follow esi/Libxml2Parser.h */
/* do not remove this comment, as it acts as barrier for the autmatic sorting */
#include "esi/ExpatParser.h"

#if HAVE_LIBXML2
static ESIParser::Register *prLibxml = 0;
#endif
#if HAVE_LIBEXPAT
static ESIParser::Register *prExpat = 0;
#endif

void Esi::Init()
{
    // register in reverse order of preference.
    // The latest registered parser will be used as default.
#if HAVE_LIBEXPAT
    assert(!prExpat); // we should be called once
    prExpat = new ESIParser::Register("expat", &ESIExpatParser::NewParser);
#endif

#if HAVE_LIBXML2
    assert(!prLibxml); // we should be called once
    prLibxml = new ESIParser::Register("libxml2", &ESILibxml2Parser::NewParser);
#endif
}

void Esi::Clean()
{
#if HAVE_LIBEXPAT
    delete prExpat;
    prExpat = NULL;
#endif

#if HAVE_LIBXML2
    delete prLibxml;
    prLibxml = NULL;
#endif
}

