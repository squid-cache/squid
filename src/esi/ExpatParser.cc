/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"

#if USE_SQUID_ESI && HAVE_LIBEXPAT

#include "esi/ExpatParser.h"

EsiParserDefinition(ESIExpatParser);

ESIExpatParser::ESIExpatParser(ESIParserClient *aClient) : theClient (aClient)
{
    /* TODO: grab the document encoding from the headers */
    p = XML_ParserCreateNS(NULL,'|');
    XML_SetUserData (myParser(), static_cast<void *>(this));
    XML_SetElementHandler(myParser(), Start, End);
    XML_SetDefaultHandler(myParser(), Default);
    XML_SetCommentHandler(myParser(), Comment);
    XML_UseParserAsHandlerArg(myParser());
}

ESIExpatParser::~ESIExpatParser()
{
    XML_ParserFree (myParser());
    p = NULL;
}

void
ESIExpatParser::Start(void *data,const XML_Char *el, const char **attr)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->start (el, attr, XML_GetSpecifiedAttributeCount (parser));
}

void
ESIExpatParser::End(void *data,const XML_Char *el)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->end (el);
}

void
ESIExpatParser::Default(void *data, const XML_Char *s, int len)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->parserDefault (s, len);
}

void
ESIExpatParser::Comment(void *data, const XML_Char *s)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->parserComment (s);
}

bool
ESIExpatParser::parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream)
{
    return XML_Parse(myParser(), dataToParse, lengthOfData, endOfStream);
}

long int
ESIExpatParser::lineNumber() const
{
    return (long int)XML_GetCurrentLineNumber(myParser());
}

char const *
ESIExpatParser::errorString() const
{
    return XML_ErrorString(XML_GetErrorCode(myParser()));
}

#endif /* USE_SQUID_ESI */

