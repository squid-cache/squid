#include "squid.h"
#include "HttpReply.h"
#include "ICAPOptions.h"
#include "TextException.h"

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

#if UNUSED_CODE
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

List<String> *ICAPOptions::parseExtFileList(const char *start, const char *end, transfer_type t_type)
{
    const String s = xstrndup(start, end - start - 1);
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

#endif

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
    if (httpHeaderGetByNameListMember(h, "Methods", "REQMOD", ',').size())
        cfgMethod(ICAP::methodReqmod);

    if (httpHeaderGetByNameListMember(h, "Methods", "RESPMOD", ',').size())
        cfgMethod(ICAP::methodRespmod);

    service = httpHeaderGetByName(h, "Service");

    serviceId = httpHeaderGetByName(h, "ServiceId");

    istag = httpHeaderGetByName(h, "ISTag");

    if (httpHeaderGetByName(h, "Opt-body-type").size())
        error = "ICAP service returns unsupported OPTIONS body";

    cfgIntHeader(h, "Max-Connections", max_connections);

    cfgIntHeader(h, "Options-TTL", theTTL);

    theTimestamp = httpHeaderGetTime(h, HDR_DATE);

    if (theTimestamp < 0)
        theTimestamp = squid_curtime;

    if (httpHeaderGetByNameListMember(h, "Allow", "204", ',').size())
        allow204 = true;

    cfgIntHeader(h, "Preview", preview);

#if 0

    if (!strncasecmp("Transfer-Preview", start, 16))
        headers->transfer_preview = parseExtFileList(value_start, end, TRANSFER_PREVIEW);

    if (!strncasecmp("Transfer-Ignore", start, 15))
        headers->transfer_ignore = parseExtFileList(value_start, end, TRANSFER_IGNORE);

    if (!strncasecmp("Transfer-Complete", start, 17))
        headers->transfer_complete = parseExtFileList(value_start, end, TRANSFER_COMPLETE);

#endif
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
