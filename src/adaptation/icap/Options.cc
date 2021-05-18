/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/Options.h"
#include "base/TextException.h"
#include "HttpReply.h"
#include "SquidTime.h"
#include "StrList.h"
#include "wordlist.h"

Adaptation::Icap::Options::Options() :
    error("unconfigured"),
    max_connections(-1),
    allow204(false),
    allow206(false),
    preview(-1),
    theTTL(-1),
    theTimestamp(0)
{
    theTransfers.preview.name = "Transfer-Preview";
    theTransfers.preview.kind = xferPreview;
    theTransfers.ignore.name = "Transfer-Ignore";
    theTransfers.ignore.kind = xferIgnore;
    theTransfers.complete.name = "Transfer-Complete";
    theTransfers.complete.kind = xferComplete;

    // Section 4.10.2 of RFC 3507 says that default is no Preview
    // TODO: provide a squid.conf option to overwrite the default
    theTransfers.byDefault = &theTransfers.complete;
}

Adaptation::Icap::Options::~Options()
{
}

// future optimization note: this method is called by ICAP ACL code at least
// twice for each HTTP message to see if the message should be ignored. For any
// non-ignored HTTP message, ICAP calls to check whether a preview is needed.
Adaptation::Icap::Options::TransferKind
Adaptation::Icap::Options::transferKind(const SBuf &urlPath) const
{
    if (theTransfers.preview.matches(urlPath))
        return xferPreview;

    if (theTransfers.complete.matches(urlPath))
        return xferComplete;

    if (theTransfers.ignore.matches(urlPath))
        return xferIgnore;

    debugs(93,7, "url " << urlPath << " matches no extensions; " <<
           "using default: " << theTransfers.byDefault->name);
    return theTransfers.byDefault->kind;
}

bool Adaptation::Icap::Options::valid() const
{
    return !error;
}

bool Adaptation::Icap::Options::fresh() const
{
    return squid_curtime <= expire();
}

int Adaptation::Icap::Options::ttl() const
{
    Must(valid());
    return theTTL >= 0 ? theTTL : TheConfig.default_options_ttl;
}

time_t Adaptation::Icap::Options::expire() const
{
    Must(valid());
    return theTimestamp + ttl();
}

void Adaptation::Icap::Options::configure(const HttpReply *reply)
{
    error = NULL; // reset initial "unconfigured" value (or an old error?)

    const HttpHeader *h = &reply->header;

    if (reply->sline.status() != Http::scOkay)
        error = "unsupported status code of OPTIONS response";

    // Methods
    if (h->hasByNameListMember("Methods", "REQMOD", ','))
        cfgMethod(ICAP::methodReqmod);

    if (h->hasByNameListMember("Methods", "RESPMOD", ','))
        cfgMethod(ICAP::methodRespmod);

    service = h->getByName("Service");

    serviceId = h->getByName("ServiceId");

    istag = h->getByName("ISTag");

    if (h->getByName("Opt-body-type").size()) {
        // TODO: add a class to rate-limit such warnings using FadingCounter
        debugs(93,DBG_IMPORTANT, "WARNING: Ignoring unsupported ICAP " <<
               "OPTIONS body; type: " << h->getByName("Opt-body-type"));
        // Do not set error, assuming the response headers are valid.
    }

    cfgIntHeader(h, "Max-Connections", max_connections);
    if (max_connections == 0)
        debugs(93, DBG_IMPORTANT, "WARNING: Max-Connections is set to zero! ");

    cfgIntHeader(h, "Options-TTL", theTTL);

    theTimestamp = h->getTime(Http::HdrType::DATE);

    if (theTimestamp < 0)
        theTimestamp = squid_curtime;

    if (h->hasListMember(Http::HdrType::ALLOW, "204", ','))
        allow204 = true;

    if (h->hasListMember(Http::HdrType::ALLOW, "206", ','))
        allow206 = true;

    cfgIntHeader(h, "Preview", preview);

    cfgTransferList(h, theTransfers.preview);
    cfgTransferList(h, theTransfers.ignore);
    cfgTransferList(h, theTransfers.complete);
}

void Adaptation::Icap::Options::cfgMethod(ICAP::Method m)
{
    Must(m != ICAP::methodNone);
    methods.push_back(m);
}

// TODO: HttpHeader should provide a general method for this type of conversion
void Adaptation::Icap::Options::cfgIntHeader(const HttpHeader *h, const char *fname, int &value)
{
    const String s = h->getByName(fname);

    if (s.size() && xisdigit(*s.termedBuf()))
        value = atoi(s.termedBuf());
    else
        value = -1;

    debugs(93,5, HERE << "int header: " << fname << ": " << value);
}

void Adaptation::Icap::Options::cfgTransferList(const HttpHeader *h, TransferList &list)
{
    const String buf = h->getByName(list.name);
    bool foundStar = false;
    list.parse(buf, foundStar);

    if (foundStar) {
        theTransfers.byDefault = &list;
        debugs(93,5, HERE << "set default transfer to " << list.name);
    }

    list.report(5, "Adaptation::Icap::Options::cfgTransferList: ");
}

/* Adaptation::Icap::Options::TransferList */

Adaptation::Icap::Options::TransferList::TransferList(): extensions(NULL), name(NULL),
    kind(xferNone)
{
};

Adaptation::Icap::Options::TransferList::~TransferList()
{
    wordlistDestroy(&extensions);
};

void Adaptation::Icap::Options::TransferList::add(const char *extension)
{
    wordlistAdd(&extensions, extension);
};

bool Adaptation::Icap::Options::TransferList::matches(const SBuf &urlPath) const
{
    const SBuf::size_type urlLen = urlPath.length();
    for (wordlist *e = extensions; e; e = e->next) {
        // optimize: store extension lengths
        const size_t eLen = strlen(e->key);

        // assume URL contains at least '/' before the extension
        if (eLen < urlLen) {
            const size_t eOff = urlLen - eLen;
            // RFC 3507 examples imply that extensions come without leading '.'
            if (urlPath[eOff-1] == '.' && urlPath.substr(eOff).cmp(e->key, eLen) == 0) {
                debugs(93,7, "url " << urlPath << " matches " << name << " extension " << e->key);
                return true;
            }
        }
    }
    debugs(93,8, "url " << urlPath << " matches no " << name << " extensions");
    return false;
}

void Adaptation::Icap::Options::TransferList::parse(const String &buf, bool &foundStar)
{
    foundStar = false;

    const char *item;
    const char *pos = NULL;
    int ilen;
    while (strListGetItem(&buf, ',', &item, &ilen, &pos)) {
        if (ilen == 1 && *item == '*')
            foundStar = true;
        else {
            const char *tmp = xstrndup(item, ilen+1);
            add(tmp);
            xfree(tmp);
        }
    }
}

void Adaptation::Icap::Options::TransferList::report(int level, const char *prefix) const
{
    if (extensions) {
        for (wordlist *e = extensions; e; e = e->next)
            debugs(93,level, prefix << name << ": " << e->key);
    } else {
        debugs(93,level, prefix << "no " << name << " extensions");
    }
}

