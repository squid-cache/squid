#include "squid.h"
#include "wordlist.h"
#include "HttpReply.h"
#include "ICAPOptions.h"
#include "TextException.h"
#include "ICAPConfig.h"
#include "SquidTime.h"

extern ICAPConfig TheICAPConfig;

ICAPOptions::ICAPOptions(): error("unconfigured"),
        max_connections(-1), allow204(false),
        preview(-1), theTTL(-1)
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

ICAPOptions::~ICAPOptions()
{
}

// future optimization note: this method is called by ICAP ACL code at least
// twice for each HTTP message to see if the message should be ignored. For any
// non-ignored HTTP message, ICAP calls to check whether a preview is needed.
ICAPOptions::TransferKind ICAPOptions::transferKind(const String &urlPath) const
{
    if (theTransfers.preview.matches(urlPath))
        return xferPreview;

    if (theTransfers.complete.matches(urlPath))
        return xferComplete;

    if (theTransfers.ignore.matches(urlPath))
        return xferIgnore;

    debugs(93,7, "ICAPOptions url " << urlPath << " matches no extensions; " <<
        "using default: " << theTransfers.byDefault->name);
    return theTransfers.byDefault->kind;
}

bool ICAPOptions::valid() const
{
    return !error;
}

bool ICAPOptions::fresh() const
{
    return squid_curtime <= expire();
}

int ICAPOptions::ttl() const
{
    Must(valid());
    return theTTL >= 0 ? theTTL : TheICAPConfig.default_options_ttl;
}

time_t ICAPOptions::expire() const
{
    Must(valid());
    return theTimestamp + ttl();
}

void ICAPOptions::configure(const HttpReply *reply)
{
    error = NULL; // reset initial "unconfigured" value (or an old error?)

    const HttpHeader *h = &reply->header;

    if (reply->sline.status != 200)
        error = "unsupported status code of OPTIONS response";

    // Methods
    if (h->hasByNameListMember("Methods", "REQMOD", ','))
        cfgMethod(ICAP::methodReqmod);

    if (h->hasByNameListMember("Methods", "RESPMOD", ','))
        cfgMethod(ICAP::methodRespmod);

    service = h->getByName("Service");

    serviceId = h->getByName("ServiceId");

    istag = h->getByName("ISTag");

    if (h->getByName("Opt-body-type").size())
        error = "ICAP service returns unsupported OPTIONS body";

    cfgIntHeader(h, "Max-Connections", max_connections);

    cfgIntHeader(h, "Options-TTL", theTTL);

    theTimestamp = h->getTime(HDR_DATE);

    if (theTimestamp < 0)
        theTimestamp = squid_curtime;

    if (h->hasListMember(HDR_ALLOW, "204", ','))
        allow204 = true;

    cfgIntHeader(h, "Preview", preview);

    cfgTransferList(h, theTransfers.preview);
    cfgTransferList(h, theTransfers.ignore);
    cfgTransferList(h, theTransfers.complete);
}

void ICAPOptions::cfgMethod(ICAP::Method m)
{
    Must(m != ICAP::methodNone);
    methods += m;
}

// TODO: HttpHeader should provide a general method for this type of conversion
void ICAPOptions::cfgIntHeader(const HttpHeader *h, const char *fname, int &value)
{
    const String s = h->getByName(fname);

    if (s.size() && xisdigit(*s.buf()))
        value = atoi(s.buf());
    else
        value = -1;

    debugs(93,5, "ICAPOptions::cfgIntHeader " << fname << ": " << value);
}

void ICAPOptions::cfgTransferList(const HttpHeader *h, TransferList &list)
{
    const String buf = h->getByName(list.name);
    bool foundStar = false;
    list.parse(buf, foundStar);

    if (foundStar) {
        theTransfers.byDefault = &list;
        debugs(93,5, "ICAPOptions::cfgTransferList: " <<
            "set default transfer to " << list.name);
    }

    list.report(5, "ICAPOptions::cfgTransferList: ");
}


/* ICAPOptions::TransferList */

ICAPOptions::TransferList::TransferList(): extensions(NULL), name(NULL),
    kind(xferNone) {
};

ICAPOptions::TransferList::~TransferList() {
    wordlistDestroy(&extensions);
};

void ICAPOptions::TransferList::add(const char *extension) {
    wordlistAdd(&extensions, extension);
};

bool ICAPOptions::TransferList::matches(const String &urlPath) const {
    const int urlLen = urlPath.size();
    for (wordlist *e = extensions; e; e = e->next) {
        // optimize: store extension lengths
        const int eLen = strlen(e->key);

        // assume URL contains at least '/' before the extension
        if (eLen < urlLen) {
            const int eOff = urlLen - eLen;
            // RFC 3507 examples imply that extensions come without leading '.'
            if (urlPath.buf()[eOff-1] == '.' &&
                strcmp(urlPath.buf() + eOff, e->key) == 0) {
                debugs(93,7, "ICAPOptions url " << urlPath << " matches " <<
                    name << " extension " << e->key);
                return true;
            }
        }
    }
    debugs(93,8, "ICAPOptions url " << urlPath << " matches no " << name << " extensions");
    return false;
}

void ICAPOptions::TransferList::parse(const String &buf, bool &foundStar) {
    foundStar = false;

    const char *item;
    const char *pos = NULL;
    int ilen;
    while (strListGetItem(&buf, ',', &item, &ilen, &pos)) {
        if (ilen == 1 && *item == '*')
            foundStar = true;
        else
            add(xstrndup(item, ilen+1));
    }
}

void ICAPOptions::TransferList::report(int level, const char *prefix) const {
    if (extensions) {
        for (wordlist *e = extensions; e; e = e->next)
            debugs(93,level, prefix << name << ": " << e->key);
    } else {
        debugs(93,level, prefix << "no " << name << " extensions");
    }
}
