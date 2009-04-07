#include "squid.h"
#include "esi/Module.h"
#include "esi/CustomParser.h"
#include "esi/Libxml2Parser.h"
#include "esi/ExpatParser.h" /* must follow esi/Libxml2Parser.h */

static ESIParser::Register *prCustom = 0;
static ESIParser::Register *prLibxml = 0;
static ESIParser::Register *prExpat = 0;

void Esi::Init()
{
    assert(!prCustom); // we should be called once
    prCustom = new ESIParser::Register("custom", &ESICustomParser::NewParser);
    prLibxml = new ESIParser::Register("libxml2", &ESILibxml2Parser::NewParser);
    prExpat = new ESIParser::Register("expat", &ESIExpatParser::NewParser);
}

void Esi::Clean()
{
    assert(prCustom); // we should be called once, and only after Init()

    delete prExpat;
    delete prLibxml;
    delete prCustom;

    prExpat = NULL;
    prLibxml = NULL;
    prCustom = NULL;
}
