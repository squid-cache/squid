/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * The ESI Libxml2 parser is Copyright (c) 2004 by Joachim Bauch
 * http://www.joachim-bauch.de
 * mail@joachim-bauch.de
 */

#include "squid.h"

#if USE_SQUID_ESI && HAVE_LIBXML2

#include "esi/Libxml2Parser.h"

// the global document that will store the resolved entity
// definitions
static htmlDocPtr entity_doc = NULL;

EsiParserDefinition(ESILibxml2Parser);

// the SAX callback functions
void esi_startElementSAXFunc(void * ctx, const xmlChar * name, const xmlChar ** atts)
{
    int count=0;
    xmlChar **tmp = (xmlChar **)atts;

    while (tmp && *tmp != NULL) {
        ++count;
        ++tmp;
    }

    // we increased on every key and value
    count /= 2;

    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;

    p->getClient()->start((const char *)name, (const char **)atts, count);
}

void esi_endElementSAXFunc(void * ctx, const xmlChar * name)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->end((const char *)name);
}

void esi_commentSAXFunc(void * ctx, const xmlChar * value)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserComment((const char *)value);
}

void esi_charactersSAXFunc(void *ctx, const xmlChar *ch, int len)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserDefault((const char *)ch, len);
}

xmlEntityPtr esi_getEntitySAXFunc(void * ctx,  const xmlChar * name)
{
    xmlEntityPtr res = xmlGetDocEntity(entity_doc, name);

    if (res == NULL) {
        const htmlEntityDesc *ent = htmlEntityLookup(name);

        if (ent != NULL) {
            char tmp[32];
            snprintf(tmp, 32, "&#%d;", ent->value);
            res = xmlAddDocEntity(entity_doc, (const xmlChar *)name, XML_INTERNAL_GENERAL_ENTITY, NULL, NULL, (const xmlChar *)tmp);
        }
    }

    return res;
}

ESILibxml2Parser::ESILibxml2Parser(ESIParserClient *aClient) : theClient (aClient)
{
    xmlSAXHandler sax;
    htmlDefaultSAXHandlerInit();
    memset(&sax, 0, sizeof(sax));
    sax.startElement = esi_startElementSAXFunc;
    sax.endElement = esi_endElementSAXFunc;
    sax.comment = esi_commentSAXFunc;
    sax.characters = esi_charactersSAXFunc;
    sax.getEntity = esi_getEntitySAXFunc;

    /* TODO: grab the document encoding from the headers */
    parser = xmlCreatePushParserCtxt(&sax, static_cast<void *>(this), NULL, 0, NULL);
    xmlSetFeature(parser, "substitute entities", 0);

    if (entity_doc == NULL)
        entity_doc = htmlNewDoc(NULL, NULL);
}

ESILibxml2Parser::~ESILibxml2Parser()
{
    xmlFreeParserCtxt(parser);
    parser = NULL;
}

bool
ESILibxml2Parser::parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream)
{
    return (xmlParseChunk(parser, dataToParse, lengthOfData, endOfStream) == 0);
}

long int
ESILibxml2Parser::lineNumber() const
{
    return (long int)xmlSAX2GetLineNumber(parser);
}

char const *
ESILibxml2Parser::errorString() const
{
    xmlErrorPtr error = xmlGetLastError();

    if (error == NULL)
        return NULL;

    return error->message;
}

#endif /* USE_SQUID_ESI */

