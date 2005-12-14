#include "squid.h"
#include "HttpReply.h"
#include "ICAPOptions.h"
#include "TextException.h"
#include "ICAPConfig.h"

extern ICAPConfig TheICAPConfig;

ICAPOptions::ICAPOptions(): error("unconfigured"), method(ICAP::methodNone),
        max_connections(-1), allow204(false),
        preview(-1), theTTL(-1), transfer_ext(NULL)
{
    transfers.preview = transfers.ignore = transfers.complete = NULL;
    transfers.other = TRANSFER_NONE;
};

ICAPOptions::~ICAPOptions()
{
    delete transfers.preview;
    delete transfers.ignore;
    delete transfers.complete;
    delete transfer_ext;
};

ICAPOptions::transfer_type ICAPOptions::getTransferExt(const char *s)
{

    if (transfer_ext) {
        List<TransferPair> *data = transfer_ext;

        while (data) {
            if (*(data->element.ext) == *s) {
                return data->element.type;
            }

            data = data->next;
        }
    }

    return TRANSFER_NONE;
}

void ICAPOptions::insertTransferExt(const char *t, transfer_type t_type)
{
    List<TransferPair> **Tail;
    TransferPair t_ext;

    if (t == "*") {
        transfers.other = t_type;
        return;
    }

    for (Tail = &transfer_ext; *Tail; Tail = &((*Tail)->next)) {
        if (*(*Tail)->element.ext == *t) {
            (*Tail)->element.type = t_type;
            return;
        }
    }

    t_ext.ext = xstrdup(t);
    t_ext.type = t_type;
    List<TransferPair> *q = new List<TransferPair>(t_ext);
    *(Tail) = q;

};

void ICAPOptions::cfgTransferListHeader(const HttpHeader *h, const char *fname, transfer_type t_type)
{
    const String s = httpHeaderGetByName(h, fname);

    if (!s.size())
        return;

    if (t_type == TRANSFER_PREVIEW)
        transfers.preview = parseExtFileList(s.buf(), s.buf() + s.size(), t_type);
    else if (t_type == TRANSFER_IGNORE)
        transfers.ignore = parseExtFileList(s.buf(), s.buf() + s.size(), t_type);
    else if (t_type == TRANSFER_COMPLETE)
        transfers.complete = parseExtFileList(s.buf(), s.buf() + s.size(), t_type);
    else
        fatalf("Unexpected transfer_type at %s:%d", __FILE__,__LINE__);
}

List<String> *ICAPOptions::parseExtFileList(const char *start, const char *end, transfer_type t_type)
{
    const String s = xstrndup(start, end - start + 1);
    const char *item;
    const char *pos = NULL;
    char *fext = NULL;
    int ilen;
    String t = NULL;

    List<String> **Tail;
    List<String> *H;

    for (Tail = &H; *Tail; Tail = &((*Tail)->next))

        ;
    while (strListGetItem(&s, ',', &item, &ilen, &pos)) {
        fext = xstrndup(item, ilen + 1);
        t = fext;
        List<String> *q = new List<String> (t);
        *(Tail) = q;
        Tail = &q->next;
        insertTransferExt(fext, t_type);
    }

    return H;
}

bool ICAPOptions::valid() const
{
    return !error;
}

bool ICAPOptions::fresh() const
{
    return squid_curtime <= expire();
}

time_t ICAPOptions::expire() const
{
    Must(valid());
    return theTTL >= 0 ? theTimestamp + theTTL : -1;
}

void ICAPOptions::configure(const HttpReply *reply)
{
    error = NULL; // reset initial "unconfigured" value (or an old error?)

    const HttpHeader *h = &reply->header;

    if (reply->sline.status != 200)
        error = "unsupported status code of OPTIONS response";

    // Methods
    if (httpHeaderHasByNameListMember(h, "Methods", "REQMOD", ','))
        cfgMethod(ICAP::methodReqmod);

    if (httpHeaderHasByNameListMember(h, "Methods", "RESPMOD", ','))
        cfgMethod(ICAP::methodRespmod);

    service = httpHeaderGetByName(h, "Service");

    serviceId = httpHeaderGetByName(h, "ServiceId");

    istag = httpHeaderGetByName(h, "ISTag");

    if (httpHeaderGetByName(h, "Opt-body-type").size())
        error = "ICAP service returns unsupported OPTIONS body";

    cfgIntHeader(h, "Max-Connections", max_connections);

    cfgIntHeader(h, "Options-TTL", theTTL);

    if (theTTL < 0)
        theTTL = TheICAPConfig.default_options_ttl;

    theTimestamp = httpHeaderGetTime(h, HDR_DATE);

    if (theTimestamp < 0)
        theTimestamp = squid_curtime;

    if (httpHeaderHasListMember(h, HDR_ALLOW, "204", ','))
        allow204 = true;

    cfgIntHeader(h, "Preview", preview);

    cfgTransferListHeader(h, "Transfer-Preview", TRANSFER_PREVIEW);

    cfgTransferListHeader(h, "Transfer-Ignore", TRANSFER_IGNORE);

    cfgTransferListHeader(h, "Transfer-Complete", TRANSFER_COMPLETE);
}

void ICAPOptions::cfgMethod(ICAP::Method m)
{
    Must(m != ICAP::methodNone);

    if (method == ICAP::methodNone)
        method = m;
    else
        error = "the service claims to support several request methods";
}

// TODO: HttpHeader should provide a general method for this type of conversion
void ICAPOptions::cfgIntHeader(const HttpHeader *h, const char *fname, int &value)
{
    const String s = httpHeaderGetByName(h, fname);

    if (s.size() && xisdigit(*s.buf()))
        value = atoi(s.buf());
    else
        value = -1;
}
