/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 10    Gopher */

#include "squid.h"
#include "clients/Client.h"
#include "comm.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "globals.h"
#include "gopher.h"
#include "html_quote.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "mime.h"
#include "parser/Tokenizer.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "tools.h"

#if USE_DELAY_POOLS
#include "DelayPools.h"
#include "MemObject.h"
#endif

// RFC 1436 section 3.8 gopher item-type codes
#define GOPHER_FILE         '0'
#define GOPHER_DIRECTORY    '1'
#define GOPHER_CSO          '2'
#define GOPHER_ERROR        '3'
#define GOPHER_MACBINHEX    '4'
#define GOPHER_DOSBIN       '5'
#define GOPHER_UUENCODED    '6'
#define GOPHER_INDEX        '7'
#define GOPHER_TELNET       '8'
#define GOPHER_BIN          '9'
#define GOPHER_REDUNT       '+'
#define GOPHER_3270         'T'
#define GOPHER_GIF          'g'
#define GOPHER_IMAGE        'I'

// Gopher+ section 2.9 extension types
// https://github.com/jgoerzen/pygopherd/blob/master/doc/standards/Gopher%2B.txt
#define GOPHER_PLUS_IMAGE   ':'
#define GOPHER_PLUS_MOVIE   ';'
#define GOPHER_PLUS_SOUND   '<'

// non-standard item-type codes
#define GOPHER_HTML         'h'
#define GOPHER_INFO         'i'
#define GOPHER_WWW          'w'
#define GOPHER_SOUND        's'

#define GOPHER_PORT         70

#define TAB                 '\t'

// TODO CODE: should this be a protocol-specific thing?
#define TEMP_BUF_SIZE       4096

#define MAX_CSO_RESULT      1024

/**
 * Gopher Gateway Internals
 *
 * Gopher is somewhat complex and gross because it must convert from
 * the Gopher protocol to HTTP.
 */
class GopherStateData : public Client
{
    CBDATA_CLASS(GopherStateData);

public:
    GopherStateData(FwdState *aFwd) :
        AsyncJob("GopherStateData"),
        entry(aFwd->entry),
        fwd(aFwd)
    {
        *request = 0;
        buf = (char *)memAllocate(MEM_4K_BUF);
        entry->lock("gopherState");
    }
    ~GopherStateData();

    /* AsyncJob API */
    static void Start(const AsyncJob::Pointer &);
    virtual void start() override;

    /* Client API */
    virtual const Comm::ConnectionPointer &dataConnection() const override { return serverConn; }
    virtual void maybeReadVirginBody() override;
    virtual void abortAll(const char *reason) override { mustStop(reason); }
    virtual void handleRequestBodyProducerAborted() override { abortTransaction("request body producer aborted"); }
    virtual void sentRequestBody(const CommIoCbParams &) override { /* not supported */}
    virtual void doneSendingRequestBody() override { /* not supported */ }
    virtual void closeServer() override { serverConn->close(); }
    virtual bool doneWithServer() const override { return Comm::IsConnOpen(serverConn); }
    virtual bool mayReadVirginReplyBody() const override { return !doneWithServer(); }
    virtual void noteDelayAwareReadChance() override { /* not implemented */ }

    /// URL for icon to display (or nil), given the Gopher item-type code.
    /// The returned c-string is invalidated by the next call to this function.
    const char *iconUrl(const char) const;

    /// generate and send Gopher format request to server/peer
    void sendRequest();

    /// called when Gopher request is completely sent
    void wroteLast(const CommIoCbParams &);

    /// called when Gopher reply data is available
    void readReply(const CommIoCbParams &);

    /// callback handler for early closure of server/peer connection
    void serverConnClosed(const CommCloseCbParams &);

    /// callback handler for timeouts on server/peer connection
    void serverTimeout(const CommTimeoutCbParams &);

public: /* replicates ::Client API */
    StoreEntry *entry = nullptr;
    FwdState::Pointer fwd;
    const char *doneWithFwd = nullptr;

public:
    enum {
        NORMAL,
        HTML_DIR,
        HTML_INDEX_RESULT,
        HTML_CSO_RESULT,
        HTML_INDEX_PAGE,
        HTML_CSO_PAGE
    } conversion = NORMAL;
    int HTML_header_added = 0;
    int HTML_pre = 0;
    char type_id = GOPHER_FILE;
    char request[MAX_URL];

    /// some received bytes ignored due to internal buffer capacity limits
    bool overflowed = false;

    int cso_recno = 0;

    /// the number of not-yet-parsed Gopher line bytes in this->buf
    int len = 0;

    char *buf = nullptr; /* pts to a 4k page */
    HttpReply::Pointer reply_;
    SBuf inBuf;

private:
    AsyncCall::Pointer closeHandler;
};

CBDATA_CLASS_INIT(GopherStateData);

static void gopherMimeCreate(GopherStateData *);
static void gopher_request_parse(const HttpRequest * req,
                                 char *type_id,
                                 char *request);
static void gopherEndHTML(GopherStateData *);
static void gopherToHTML(GopherStateData *, char *inbuf, int len);

static char def_gopher_bin[] = "www/unknown";

static char def_gopher_text[] = "text/plain";

GopherStateData::~GopherStateData()
{
    if (entry)
        entry->unlock("gopherState");

    if (buf)
        memFree(buf, MEM_4K_BUF);
}

const char *
GopherStateData::iconUrl(const char gtype) const
{
    switch (gtype) {

    case GOPHER_DIRECTORY:
        return mimeGetIconURL("internal-menu");

    case GOPHER_HTML:
    case GOPHER_FILE:
        return mimeGetIconURL("internal-text");

    case GOPHER_INDEX:
    case GOPHER_CSO:
        return mimeGetIconURL("internal-index");

    case GOPHER_IMAGE:
    case GOPHER_GIF:
    case GOPHER_PLUS_IMAGE:
        return mimeGetIconURL("internal-image");

    case GOPHER_SOUND:
    case GOPHER_PLUS_SOUND:
        return mimeGetIconURL("internal-sound");

    case GOPHER_PLUS_MOVIE:
        return mimeGetIconURL("internal-movie");

    case GOPHER_TELNET:
    case GOPHER_3270:
        return mimeGetIconURL("internal-telnet");

    case GOPHER_BIN:

    case GOPHER_MACBINHEX:
    case GOPHER_DOSBIN:
    case GOPHER_UUENCODED:
        return mimeGetIconURL("internal-binary");

    case GOPHER_INFO:
        return nullptr;

    case GOPHER_WWW:
        return mimeGetIconURL("internal-link");

    default:
        return mimeGetIconURL("internal-unknown");
    }
}

/**
 * Create MIME Header for Gopher Data
 */
static void
gopherMimeCreate(GopherStateData * gopherState)
{
    StoreEntry *entry = gopherState->entry;
    const char *mime_type = NULL;
    const char *mime_enc = NULL;

    switch (gopherState->type_id) {

    case GOPHER_DIRECTORY:

    case GOPHER_INDEX:

    case GOPHER_HTML:

    case GOPHER_WWW:

    case GOPHER_CSO:
        mime_type = "text/html";
        break;

    case GOPHER_GIF:

    case GOPHER_IMAGE:

    case GOPHER_PLUS_IMAGE:
        mime_type = "image/gif";
        break;

    case GOPHER_SOUND:

    case GOPHER_PLUS_SOUND:
        mime_type = "audio/basic";
        break;

    case GOPHER_PLUS_MOVIE:
        mime_type = "video/mpeg";
        break;

    case GOPHER_MACBINHEX:

    case GOPHER_DOSBIN:

    case GOPHER_UUENCODED:

    case GOPHER_BIN:
        /* Rightnow We have no idea what it is. */
        mime_enc = mimeGetContentEncoding(gopherState->request);
        mime_type = mimeGetContentType(gopherState->request);
        if (!mime_type)
            mime_type = def_gopher_bin;
        break;

    case GOPHER_FILE:

    default:
        mime_enc = mimeGetContentEncoding(gopherState->request);
        mime_type = mimeGetContentType(gopherState->request);
        if (!mime_type)
            mime_type = def_gopher_text;
        break;
    }

    assert(entry->isEmpty());

    HttpReply *reply = new HttpReply;
    entry->buffer();
    reply->setHeaders(Http::scOkay, "Gatewaying", mime_type, -1, -1, -2);
    if (mime_enc)
        reply->header.putStr(Http::HdrType::CONTENT_ENCODING, mime_enc);

    entry->replaceHttpReply(reply);
    gopherState->reply_ = reply;
}

/**
 * Parse a gopher request into components.  By Anawat.
 */
static void
gopher_request_parse(const HttpRequest * req, char *type_id, char *request)
{
    ::Parser::Tokenizer tok(req->url.path());

    if (request)
        *request = 0;

    tok.skip('/'); // ignore failures? path could be ab-empty

    if (tok.atEnd()) {
        *type_id = GOPHER_DIRECTORY;
        return;
    }

    static const CharacterSet anyByte("UTF-8",0x00, 0xFF);

    SBuf typeId;
    (void)tok.prefix(typeId, anyByte, 1); // never fails since !atEnd()
    *type_id = typeId[0];

    if (request) {
        SBufToCstring(request, tok.remaining().substr(0, MAX_URL-1));
        /* convert %xx to char */
        rfc1738_unescape(request);
    }
}

/**
 * Parse the request to determine whether it is cachable.
 *
 * \param req   Request data.
 * \retval 0    Not cachable.
 * \retval 1    Cachable.
 */
int
gopherCachable(const HttpRequest * req)
{
    int cachable = 1;
    char type_id;
    /* parse to see type */
    gopher_request_parse(req,
                         &type_id,
                         NULL);

    switch (type_id) {

    case GOPHER_INDEX:

    case GOPHER_CSO:

    case GOPHER_TELNET:

    case GOPHER_3270:
        cachable = 0;
        break;

    default:
        cachable = 1;
    }

    return cachable;
}

static void
gopherHTMLHeader(StoreEntry * e, const char *title, const char *substring)
{
    storeAppendPrintf(e, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
    storeAppendPrintf(e, "<HTML><HEAD><TITLE>");
    storeAppendPrintf(e, title, substring);
    storeAppendPrintf(e, "</TITLE>");
    storeAppendPrintf(e, "<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n");
    storeAppendPrintf(e, "</HEAD>\n<BODY><H1>");
    storeAppendPrintf(e, title, substring);
    storeAppendPrintf(e, "</H1>\n");
}

static void
gopherHTMLFooter(StoreEntry * e)
{
    storeAppendPrintf(e, "<HR noshade size=\"1px\">\n");
    storeAppendPrintf(e, "<ADDRESS>\n");
    storeAppendPrintf(e, "Generated %s by %s (%s)\n",
                      Time::FormatRfc1123(squid_curtime),
                      getMyHostname(),
                      visible_appname_string);
    storeAppendPrintf(e, "</ADDRESS></BODY></HTML>\n");
}

static void
gopherEndHTML(GopherStateData * gopherState)
{
    StoreEntry *e = gopherState->entry;

    if (!gopherState->HTML_header_added) {
        gopherHTMLHeader(e, "Server Return Nothing", NULL);
        storeAppendPrintf(e, "<P>The Gopher query resulted in a blank response</P>");
    } else if (gopherState->HTML_pre) {
        storeAppendPrintf(e, "</PRE>\n");
    }

    gopherHTMLFooter(e);
}

/**
 * Convert Gopher to HTML.
 *
 * Borrow part of code from libwww2 came with Mosaic distribution.
 */
static void
gopherToHTML(GopherStateData * gopherState, char *inbuf, int len)
{
    char *pos = inbuf;
    char *lpos = NULL;
    char *tline = NULL;
    LOCAL_ARRAY(char, line, TEMP_BUF_SIZE);
    char *name = NULL;
    char *selector = NULL;
    char *host = NULL;
    char *port = NULL;
    char *escaped_selector = NULL;
    char gtype;
    StoreEntry *entry = NULL;

    memset(line, '\0', TEMP_BUF_SIZE);

    entry = gopherState->entry;

    if (gopherState->conversion == GopherStateData::HTML_INDEX_PAGE) {
        char *html_url = html_quote(entry->url());
        gopherHTMLHeader(entry, "Gopher Index %s", html_url);
        storeAppendPrintf(entry,
                          "<p>This is a searchable Gopher index. Use the search\n"
                          "function of your browser to enter search terms.\n"
                          "<ISINDEX>\n");
        gopherHTMLFooter(entry);
        /* now let start sending stuff to client */
        entry->flush();
        gopherState->HTML_header_added = 1;

        return;
    }

    if (gopherState->conversion == GopherStateData::HTML_CSO_PAGE) {
        char *html_url = html_quote(entry->url());
        gopherHTMLHeader(entry, "CSO Search of %s", html_url);
        storeAppendPrintf(entry,
                          "<P>A CSO database usually contains a phonebook or\n"
                          "directory.  Use the search function of your browser to enter\n"
                          "search terms.</P><ISINDEX>\n");
        gopherHTMLFooter(entry);
        /* now let start sending stuff to client */
        entry->flush();
        gopherState->HTML_header_added = 1;

        return;
    }

    SBuf outbuf;

    if (!gopherState->HTML_header_added) {
        if (gopherState->conversion == GopherStateData::HTML_CSO_RESULT)
            gopherHTMLHeader(entry, "CSO Search Result", NULL);
        else
            gopherHTMLHeader(entry, "Gopher Menu", NULL);

        outbuf.append ("<PRE>");

        gopherState->HTML_header_added = 1;

        gopherState->HTML_pre = 1;
    }

    while (pos < inbuf + len) {
        int llen;
        int left = len - (pos - inbuf);
        lpos = (char *)memchr(pos, '\n', left);
        if (lpos) {
            ++lpos;             /* Next line is after \n */
            llen = lpos - pos;
        } else {
            llen = left;
        }
        if (gopherState->len + llen >= TEMP_BUF_SIZE) {
            debugs(10, DBG_IMPORTANT, "GopherHTML: Buffer overflow. Lost some data on URL: " << entry->url()  );
            llen = TEMP_BUF_SIZE - gopherState->len - 1;
            gopherState->overflowed = true; // may already be true
        }
        if (!lpos) {
            /* there is no complete line in inbuf */
            /* copy it to temp buffer */
            /* note: llen is adjusted above */
            memcpy(gopherState->buf + gopherState->len, pos, llen);
            gopherState->len += llen;
            break;
        }
        if (gopherState->len != 0) {
            /* there is something left from last tx. */
            memcpy(line, gopherState->buf, gopherState->len);
            memcpy(line + gopherState->len, pos, llen);
            llen += gopherState->len;
            gopherState->len = 0;
        } else {
            memcpy(line, pos, llen);
        }
        line[llen + 1] = '\0';
        /* move input to next line */
        pos = lpos;

        /* at this point. We should have one line in buffer to process */

        if (*line == '.') {
            /* skip it */
            memset(line, '\0', TEMP_BUF_SIZE);
            continue;
        }

        switch (gopherState->conversion) {

        case GopherStateData::HTML_INDEX_RESULT:

        case GopherStateData::HTML_DIR: {
            tline = line;
            gtype = *tline;
            ++tline;
            name = tline;
            selector = strchr(tline, TAB);

            if (selector) {
                *selector = '\0';
                ++selector;
                host = strchr(selector, TAB);

                if (host) {
                    *host = '\0';
                    ++host;
                    port = strchr(host, TAB);

                    if (port) {
                        char *junk;
                        port[0] = ':';
                        junk = strchr(host, TAB);

                        if (junk)
                            *junk++ = 0;    /* Chop port */
                        else {
                            junk = strchr(host, '\r');

                            if (junk)
                                *junk++ = 0;    /* Chop port */
                            else {
                                junk = strchr(host, '\n');

                                if (junk)
                                    *junk++ = 0;    /* Chop port */
                            }
                        }

                        if ((port[1] == '0') && (!port[2]))
                            port[0] = 0;    /* 0 means none */
                    }

                    /* escape a selector here */
                    escaped_selector = xstrdup(rfc1738_escape_part(selector));

                    const auto icon_url = gopherState->iconUrl(gtype);

                    if ((gtype == GOPHER_TELNET) || (gtype == GOPHER_3270)) {
                        if (strlen(escaped_selector) != 0)
                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
                                           icon_url, escaped_selector, rfc1738_escape_part(host),
                                           *port ? ":" : "", port, html_quote(name));
                        else
                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
                                           icon_url, rfc1738_escape_part(host), *port ? ":" : "",
                                           port, html_quote(name));

                    } else if (gtype == GOPHER_INFO) {
                        outbuf.appendf("\t%s\n", html_quote(name));
                    } else {
                        if (strncmp(selector, "GET /", 5) == 0) {
                            /* WWW link */
                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"http://%s/%s\">%s</A>\n",
                                           icon_url, host, rfc1738_escape_unescaped(selector + 5), html_quote(name));
                        } else if (gtype == GOPHER_WWW) {
                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"gopher://%s/%c%s\">%s</A>\n",
                                           icon_url, rfc1738_escape_unescaped(selector), html_quote(name));
                        } else {
                            /* Standard link */
                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"gopher://%s/%c%s\">%s</A>\n",
                                           icon_url, host, gtype, escaped_selector, html_quote(name));
                        }
                    }

                    safe_free(escaped_selector);
                } else {
                    memset(line, '\0', TEMP_BUF_SIZE);
                    continue;
                }
            } else {
                memset(line, '\0', TEMP_BUF_SIZE);
                continue;
            }

            break;
            }           /* HTML_DIR, HTML_INDEX_RESULT */

        case GopherStateData::HTML_CSO_RESULT: {
            if (line[0] == '-') {
                int code, recno;
                char *s_code, *s_recno, *result;

                s_code = strtok(line + 1, ":\n");
                s_recno = strtok(NULL, ":\n");
                result = strtok(NULL, "\n");

                if (!result)
                    break;

                code = atoi(s_code);

                recno = atoi(s_recno);

                if (code != 200)
                    break;

                if (gopherState->cso_recno != recno) {
                    outbuf.appendf("</PRE><HR noshade size=\"1px\"><H2>Record# %d<br><i>%s</i></H2>\n<PRE>", recno, html_quote(result));
                    gopherState->cso_recno = recno;
                } else {
                    outbuf.appendf("%s\n", html_quote(result));
                }

                break;
            } else {
                int code;
                char *s_code, *result;

                s_code = strtok(line, ":");
                result = strtok(NULL, "\n");

                if (!result)
                    break;

                code = atoi(s_code);

                switch (code) {

                case 200: {
                    /* OK */
                    /* Do nothing here */
                    break;
                }

                case 102:   /* Number of matches */

                case 501:   /* No Match */

                case 502: { /* Too Many Matches */
                    /* Print the message the server returns */
                    outbuf.appendf("</PRE><HR noshade size=\"1px\"><H2>%s</H2>\n<PRE>", html_quote(result));
                    break;
                }

                }
            }

            break;
            }           /* HTML_CSO_RESULT */
        default:
            break;      /* do nothing */

        }           /* switch */

    }               /* while loop */

    if (outbuf.length() > 0) {
        entry->append(outbuf.rawContent(), outbuf.length());
        /* now let start sending stuff to client */
        entry->flush();
    }

    return;
}

void
GopherStateData::serverConnClosed(const CommCloseCbParams &params)
{
    debugs(10, 5, "FD " << params.fd << ", gopherState=" << params.data);
    doneWithFwd = "GopherStateData::serverConnClosed()"; // assume FwdState is monitoring too
    mustStop("GopherStateData::serverConnClosed");
}

void
GopherStateData::serverTimeout(const CommTimeoutCbParams &params)
{
    debugs(10, 4, params.conn << ": '" << entry->url() << "'");

    if (entry->store_status == STORE_PENDING) {
        fwd->fail(new ErrorState(ERR_READ_TIMEOUT, Http::scGatewayTimeout, fwd->request, fwd->al));
    }

    if (Comm::IsConnOpen(params.conn))
        params.conn->close();
    mustStop("GopherStateData::serverTimeout");
}

void
GopherStateData::readReply(const CommIoCbParams &io)
{
    debugs(10, 5, io.conn);

    // Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us
    if (io.flag == Comm::ERR_CLOSING) {
        debugs(10, 3, "sever socket closing");
        return;
    }

    Must(Comm::IsConnOpen(serverConn));
    Must(io.conn->fd == serverConn->fd);
    Assure(entry->isAccepting());
    Must(maybeMakeSpaceAvailable(true));

    CommIoCbParams rd(this); // will be expanded with ReadNow results
    rd.conn = io.conn;
    rd.size = entry->bytesWanted(Range<size_t>(0, inBuf.spaceSize()));

    if (rd.size <= 0) {
        delayRead();
        return;
    }

    switch (Comm::ReadNow(rd, inBuf)) {
    case Comm::INPROGRESS:
        if (inBuf.isEmpty())
            debugs(33, 2, io.conn << ": no data to process, " << xstrerr(rd.xerrno));
        maybeReadVirginBody();
        return;

    case Comm::OK:
    {
        payloadSeen += rd.size;
#if USE_DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(rd.size);
#endif

        statCounter.server.all.kbytes_in += rd.size;
        statCounter.server.other.kbytes_in += rd.size;
        ++ IOStats.Gopher.reads;

        int bin = 0;
        for (int clen = rd.size - 1; clen; ++bin)
            clen >>= 1;

        ++IOStats.Gopher.read_hist[bin];

        request->hier.notePeerRead();

        auto &req = fwd->request;
        if (req->hier.bodyBytesRead < 0) {
            req->hier.bodyBytesRead = 0;
            // first bytes read, update Reply flags:
            reply_->sources |= Http::Message::srcGopher;
        }
    }

        /* Continue to process previously read data */
    break;

    case Comm::ENDFILE: // close detected by 0-byte read
        eof = 1;

        /* Continue to process previously read data */
        break;

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
        debugs(10, 2, io.conn << ": read failure: " << xstrerr(rd.xerrno));
        const auto err = new ErrorState(ERR_READ_ERROR, Http::scBadGateway, fwd->request, fwd->al);
        err->xerrno = rd.xerrno;
        fwd->fail(err);
        closeServer();
        mustStop("GopherStateData::readReply");
        return;
    }

    /* Process next response from buffer */
    processReply();
}

void
GopherStateData::processReply()
{
    if (inBuf.isEmpty()) {
        /* Connection closed; retrieval done. */
        if (entry->isEmpty()) {
            fwd->fail(new ErrorState(ERR_ZERO_SIZE_OBJECT, Http::scServiceUnavailable, fwd->request, fwd->al));

        } else {
            /* flush the rest of data in temp buf if there is one. */
            if (conversion != GopherStateData::NORMAL)
                gopherEndHTML(this);

            entry->timestampsSet();
            entry->flush();

            if (!len && !overflowed)
                fwd->markStoredReplyAsWhole("gopher EOF after receiving/storing some bytes");

            fwd->complete();
        }
        closeServer();

    } else {
        if (conversion != GopherStateData::NORMAL) {
            gopherToHTML(this, inBuf.c_str(), inBuf.length());
        } else {
            entry->append(inBuf.rawContent(), inBuf.length());
            inBuf.clear();
        }
        maybeReadVirginBody();
    }
}

bool
GopherStateData::maybeMakeSpaceAvailable(bool doGrow)
{
    // how much we are allowed to buffer
    const int limitBuffer = Config.readAheadGap;

    if (limitBuffer < 0 || inBuf.length() >= (SBuf::size_type)limitBuffer) {
        // when buffer is at or over limit already
        debugs(10, 7, "will not read up to " << limitBuffer << ". buffer has (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConn);
        debugs(10, DBG_DATA, "buffer has {" << inBuf << "}");
        // Process buffer
        processReply();
        return false;
    }

    // how much we want to read
    const size_t read_size = calcBufferSpaceToReserve(inBuf.spaceSize(), (limitBuffer - inBuf.length()));

    if (!read_size) {
        debugs(10, 7, "will not read up to " << read_size << " into buffer (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConnection);
        return false;
    }

    // just report whether we could grow or not, do not actually do it
    if (doGrow)
        return (read_size >= 2);

    // we may need to grow the buffer
    inBuf.reserveSpace(read_size);
    debugs(10, 8, (!flags.do_next_read ? "will not" : "may") <<
           " read up to " << read_size << " bytes info buf(" << inBuf.length() << "/" << inBuf.spaceSize() <<
           ") from " << serverConnection);

    return (inBuf.spaceSize() >= 2); // only read if there is 1+ bytes of space available
}

void
GopherStateData::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(serverConn) || fd_table[serverConn->fd].closing())
        return;

    if (!maybeMakeSpaceAvailable(false))
        return;

    // must not already be waiting for read(2) ...
    assert(!Comm::MonitorsRead(serverConn->fd));

    // wait for read(2) to be possible.
    typedef CommCbMemFunT<GopherStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(10, 5, Dialer, this, GopherStateData::readReply);
    Comm::Read(serverConn, call);
}

void
GopherStateData::wroteLast(const CommIoCbParams &io)
{
    debugs(10, 5, io.conn << " size=" << io.size << " flag=" << io.flag);

    if (io.size > 0) {
        statCounter.server.other.kbytes_out += io.size;
        Client::sentRequestBody(io);
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    Assure(entry->isAccepting());

    if (io.flag) {
        const auto err = new ErrorState(ERR_WRITE_ERROR, Http::scServiceUnavailable, fwd->request, fwd->al);
        err->xerrno = io.xerrno;
        err->port = fwd->request->url.port(); // XXX: redundant?
        err->url = xstrdup(entry->url()); // XXX: redundant?
        fwd->fail(err);
        io.conn->close();
        mustStop("GopherStateData::wroteLast");
        return;
    }

    /*
     * OK. We successfully reach remote site.  Start MIME typing
     * stuff.  Do it anyway even though request is not HTML type.
     */
    entry->buffer();

    gopherMimeCreate(this);

    switch (type_id) {

    case GOPHER_DIRECTORY:
        /* we have to convert it first */
        conversion = GopherStateData::HTML_DIR;
        HTML_header_added = 0;
        break;

    case GOPHER_INDEX:
        /* we have to convert it first */
        conversion = GopherStateData::HTML_INDEX_RESULT;
        HTML_header_added = 0;
        break;

    case GOPHER_CSO:
        /* we have to convert it first */
        conversion = GopherStateData::HTML_CSO_RESULT;
        cso_recno = 0;
        HTML_header_added = 0;
        break;

    default:
        conversion = GopherStateData::NORMAL;
        entry->flush();
    }

    maybeReadVirginBody();
}

void
GopherStateData::sendRequest()
{
    MemBuf mb;
    mb.init();

    if (type_id == GOPHER_CSO) {
        const char *t = strchr(request, '?');

        if (t)
            ++t;        /* skip the ? */
        else
            t = "";

        mb.appendf("query %s\r\nquit", t);
    } else {
        if (type_id == GOPHER_INDEX) {
            if (char *t = strchr(request, '?'))
                *t = '\t';
        }
        mb.append(request, strlen(request));
    }
    mb.append("\r\n", 2);

    debugs(10, 5, fwd->serverConnection());

    typedef CommCbMemFunT<GopherStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(10, 5, Dialer, this, GopherStateData::wroteLast);
    Comm::Write(fwd->serverConnection(), &mb, call);

    if (!entry->makePublic())
        entry->makePrivate(true);
}

void
gopherStart(FwdState * fwd)
{
    debugs(10, 3, fwd->request->method << ' ' << fwd->entry->url());
    AsyncJob::Start(new GopherStateData(fwd));
}

void
GopherStateData::start()
{
    ++ statCounter.server.all.requests;

    ++ statCounter.server.other.requests;

    /* Parse url. */
    gopher_request_parse(fwd->request, &type_id, request);

    typedef CommCbMemFunT<GopherStateData, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(10, 5, Dialer, this, GopherStateData::serverConnClosed);
    comm_add_close_handler(fwd->serverConnection()->fd, closeHandler);

    if ((type_id == GOPHER_INDEX || type_id == GOPHER_CSO) && strchr(request, '?') == nullptr) {
        /* Index URL without query word */
        /* We have to generate search page back to client. No need for connection */
        gopherMimeCreate(this);

        if (type_id == GOPHER_INDEX) {
            conversion = GopherStateData::HTML_INDEX_PAGE;
        } else {
            if (type_id == GOPHER_CSO) {
                conversion = GopherStateData::HTML_CSO_PAGE;
            } else {
                conversion = GopherStateData::HTML_INDEX_PAGE;
            }
        }

        gopherToHTML(this, nullptr, 0);
        fwd->markStoredReplyAsWhole("gopher instant internal request satisfaction");
        fwd->complete();
        mustStop("gopher instant internal request satisfaction");
        return;
    }

    sendRequest();

    typedef CommCbMemFunT<GopherStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(10, 5,
                                      TimeoutDialer, this, GopherStateData::serverTimeout);
    commSetConnTimeout(fwd->serverConnection(), Config.Timeout.read, timeoutCall);
}

