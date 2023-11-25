/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

#include "base/RunnersRegistry.h"
#include "esi/Libxml2Parser.h"

#include <memory>

namespace Esi
{

class Libxml2Rr : public RegisteredRunner
{
public:
    void finalizeConfig() override
    {
        registration.reset(new ESIParser::Register("libxml2", &ESILibxml2Parser::NewParser));
    }

private:
    std::unique_ptr<ESIParser::Register> registration;
};

}

DefineRunnerRegistratorIn(Esi, Libxml2Rr);

// the global document that will store the resolved entity
// definitions
static htmlDocPtr entity_doc = nullptr;

EsiParserDefinition(ESILibxml2Parser);

// the SAX callback functions
static void
esi_startElementSAXFunc(void * ctx, const xmlChar * name, const xmlChar ** atts)
{
    int count=0;
    xmlChar **tmp = (xmlChar **)atts;

    while (tmp && *tmp != nullptr) {
        ++count;
        ++tmp;
    }

    // we increased on every key and value
    count /= 2;

    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;

    p->getClient()->start((const char *)name, (const char **)atts, count);
}

static void
esi_endElementSAXFunc(void *ctx, const xmlChar *name)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->end((const char *)name);
}

static void
esi_commentSAXFunc(void *ctx, const xmlChar *value)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserComment((const char *)value);
}

static void
esi_charactersSAXFunc(void *ctx, const xmlChar *ch, int len)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserDefault((const char *)ch, len);
}

static xmlEntityPtr
esi_getEntitySAXFunc(void * /* ctx */, const xmlChar *name)
{
    xmlEntityPtr res = xmlGetDocEntity(entity_doc, name);

    if (res == nullptr) {
        const htmlEntityDesc *ent = htmlEntityLookup(name);

        if (ent != nullptr) {
            char tmp[32];
            snprintf(tmp, 32, "&#%d;", ent->value);
            res = xmlAddDocEntity(entity_doc, (const xmlChar *)name, XML_INTERNAL_GENERAL_ENTITY, nullptr, nullptr, (const xmlChar *)tmp);
        }
    }

    return res;
}

ESILibxml2Parser::ESILibxml2Parser(ESIParserClient *aClient) : theClient (aClient)
{
    xmlSAXHandler sax;
    xmlInitParser();
    memset(&sax, 0, sizeof(sax));
    sax.startElement = esi_startElementSAXFunc;
    sax.endElement = esi_endElementSAXFunc;
    sax.comment = esi_commentSAXFunc;
    sax.characters = esi_charactersSAXFunc;
    sax.getEntity = esi_getEntitySAXFunc;

    /* TODO: grab the document encoding from the headers */
    parser = xmlCreatePushParserCtxt(&sax, static_cast<void *>(this), nullptr, 0, nullptr);

    if (entity_doc == nullptr)
        entity_doc = htmlNewDoc(nullptr, nullptr);
}

ESILibxml2Parser::~ESILibxml2Parser()
{
    xmlFreeParserCtxt(parser);
    parser = nullptr;
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
    const auto error = xmlGetLastError();

    if (error == nullptr)
        return nullptr;

    return error->message;
}

#endif /* USE_SQUID_ESI */

