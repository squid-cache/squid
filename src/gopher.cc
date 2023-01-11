/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 10    Gopher */

#include "squid.h"
#include "comm.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "FwdState.h"
#include "globals.h"
#include "html_quote.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "mime.h"
#include "parser/Tokenizer.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
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
class GopherStateData
{
    CBDATA_CLASS(GopherStateData);

public:
    GopherStateData(FwdState *aFwd) :
        entry(aFwd->entry),
        conversion(NORMAL),
        HTML_header_added(0),
        HTML_pre(0),
        type_id(GOPHER_FILE /* '0' */),
        overflowed(false),
        cso_recno(0),
        len(0),
        buf(NULL),
        fwd(aFwd)
    {
        *request = 0;
        buf = (char *)memAllocate(MEM_4K_BUF);
        entry->lock("gopherState");
        *replybuf = 0;
    }

    ~GopherStateData();

public:
    StoreEntry *entry;
    enum {
        NORMAL,
        HTML_DIR,
        HTML_INDEX_RESULT,
        HTML_CSO_RESULT,
        HTML_INDEX_PAGE,
        HTML_CSO_PAGE
    } conversion;
    int HTML_header_added;
    int HTML_pre;
    char type_id;
    char request[MAX_URL];

    /// some received bytes ignored due to internal buffer capacity limits
    bool overflowed;

    int cso_recno;

    /// the number of not-yet-parsed Gopher line bytes in this->buf
    int len;

    char *buf;          /* pts to a 4k page */
    Comm::ConnectionPointer serverConn;
    FwdState::Pointer fwd;
    HttpReply::Pointer reply_;
    char replybuf[BUFSIZ];
};

CBDATA_CLASS_INIT(GopherStateData);

static CLCB gopherStateFree;
static void gopherMimeCreate(GopherStateData *);
static void gopher_request_parse(const HttpRequest * req,
                                 char *type_id,
                                 char *request);
static void gopherEndHTML(GopherStateData *);
static void gopherToHTML(GopherStateData *, char *inbuf, int len);
static CTCB gopherTimeout;
static IOCB gopherReadReply;
static IOCB gopherSendComplete;
static PF gopherSendRequest;

static char def_gopher_bin[] = "www/unknown";

static char def_gopher_text[] = "text/plain";

static void
gopherStateFree(const CommCloseCbParams &params)
{
    GopherStateData *gopherState = (GopherStateData *)params.data;
    // Assume that FwdState is monitoring and calls noteClosure(). See XXX about
    // Connection sharing with FwdState in gopherStart().
    delete gopherState;
}

GopherStateData::~GopherStateData()
{
    if (entry)
        entry->unlock("gopherState");

    if (buf)
        memFree(buf, MEM_4K_BUF);
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
                      mkrfc1123(squid_curtime),
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
    const char *icon_url = NULL;
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

                    switch (gtype) {

                    case GOPHER_DIRECTORY:
                        icon_url = mimeGetIconURL("internal-menu");
                        break;

                    case GOPHER_HTML:

                    case GOPHER_FILE:
                        icon_url = mimeGetIconURL("internal-text");
                        break;

                    case GOPHER_INDEX:

                    case GOPHER_CSO:
                        icon_url = mimeGetIconURL("internal-index");
                        break;

                    case GOPHER_IMAGE:

                    case GOPHER_GIF:

                    case GOPHER_PLUS_IMAGE:
                        icon_url = mimeGetIconURL("internal-image");
                        break;

                    case GOPHER_SOUND:

                    case GOPHER_PLUS_SOUND:
                        icon_url = mimeGetIconURL("internal-sound");
                        break;

                    case GOPHER_PLUS_MOVIE:
                        icon_url = mimeGetIconURL("internal-movie");
                        break;

                    case GOPHER_TELNET:

                    case GOPHER_3270:
                        icon_url = mimeGetIconURL("internal-telnet");
                        break;

                    case GOPHER_BIN:

                    case GOPHER_MACBINHEX:

                    case GOPHER_DOSBIN:

                    case GOPHER_UUENCODED:
                        icon_url = mimeGetIconURL("internal-binary");
                        break;

                    case GOPHER_INFO:
                        icon_url = NULL;
                        break;

                    case GOPHER_WWW:
                        icon_url = mimeGetIconURL("internal-link");
                        break;

                    default:
                        icon_url = mimeGetIconURL("internal-unknown");
                        break;
                    }

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

static void
gopherTimeout(const CommTimeoutCbParams &io)
{
    GopherStateData *gopherState = static_cast<GopherStateData *>(io.data);
    debugs(10, 4, HERE << io.conn << ": '" << gopherState->entry->url() << "'" );

    gopherState->fwd->fail(new ErrorState(ERR_READ_TIMEOUT, Http::scGatewayTimeout, gopherState->fwd->request, gopherState->fwd->al));

    if (Comm::IsConnOpen(io.conn))
        io.conn->close();
}

/**
 * This will be called when data is ready to be read from fd.
 * Read until error or connection closed.
 */
static void
gopherReadReply(const Comm::ConnectionPointer &conn, char *buf, size_t len, Comm::Flag flag, int xerrno, void *data)
{
    GopherStateData *gopherState = (GopherStateData *)data;
    StoreEntry *entry = gopherState->entry;
    int clen;
    int bin;
    size_t read_sz = BUFSIZ;
#if USE_DELAY_POOLS
    DelayId delayId = entry->mem_obj->mostBytesAllowed();
#endif

    /* Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us */

    if (flag == Comm::ERR_CLOSING) {
        return;
    }

    assert(buf == gopherState->replybuf);

    // XXX: Should update delayId, statCounter, etc. before bailing
    if (!entry->isAccepting()) {
        debugs(10, 3, "terminating due to bad " << *entry);
        // TODO: Do not abuse connection for triggering cleanup.
        gopherState->serverConn->close();
        return;
    }

#if USE_DELAY_POOLS
    read_sz = delayId.bytesWanted(1, read_sz);
#endif

    /* leave one space for \0 in gopherToHTML */

    if (flag == Comm::OK && len > 0) {
#if USE_DELAY_POOLS
        delayId.bytesIn(len);
#endif

        statCounter.server.all.kbytes_in += len;
        statCounter.server.other.kbytes_in += len;
    }

    debugs(10, 5, HERE << conn << " read len=" << len);

    if (flag == Comm::OK && len > 0) {
        AsyncCall::Pointer nil;
        commSetConnTimeout(conn, Config.Timeout.read, nil);
        ++IOStats.Gopher.reads;

        for (clen = len - 1, bin = 0; clen; ++bin)
            clen >>= 1;

        ++IOStats.Gopher.read_hist[bin];

        HttpRequest *req = gopherState->fwd->request;
        if (req->hier.bodyBytesRead < 0) {
            req->hier.bodyBytesRead = 0;
            // first bytes read, update Reply flags:
            gopherState->reply_->sources |= Http::Message::srcGopher;
        }

        req->hier.bodyBytesRead += len;
    }

    if (flag != Comm::OK) {
        debugs(50, DBG_IMPORTANT, MYNAME << "error reading: " << xstrerr(xerrno));

        if (ignoreErrno(xerrno)) {
            AsyncCall::Pointer call = commCbCall(5,4, "gopherReadReply",
                                                 CommIoCbPtrFun(gopherReadReply, gopherState));
            comm_read(conn, buf, read_sz, call);
        } else {
            const auto err = new ErrorState(ERR_READ_ERROR, Http::scInternalServerError, gopherState->fwd->request, gopherState->fwd->al);
            err->xerrno = xerrno;
            gopherState->fwd->fail(err);
            gopherState->serverConn->close();
        }
    } else if (len == 0 && entry->isEmpty()) {
        gopherState->fwd->fail(new ErrorState(ERR_ZERO_SIZE_OBJECT, Http::scServiceUnavailable, gopherState->fwd->request, gopherState->fwd->al));
        gopherState->serverConn->close();
    } else if (len == 0) {
        /* Connection closed; retrieval done. */
        /* flush the rest of data in temp buf if there is one. */

        if (gopherState->conversion != GopherStateData::NORMAL)
            gopherEndHTML(gopherState);

        entry->timestampsSet();
        entry->flush();

        if (!gopherState->len && !gopherState->overflowed)
            gopherState->fwd->markStoredReplyAsWhole("gopher EOF after receiving/storing some bytes");

        gopherState->fwd->complete();
        gopherState->serverConn->close();
    } else {
        if (gopherState->conversion != GopherStateData::NORMAL) {
            gopherToHTML(gopherState, buf, len);
        } else {
            entry->append(buf, len);
        }
        AsyncCall::Pointer call = commCbCall(5,4, "gopherReadReply",
                                             CommIoCbPtrFun(gopherReadReply, gopherState));
        comm_read(conn, buf, read_sz, call);
    }
}

/**
 * This will be called when request write is complete. Schedule read of reply.
 */
static void
gopherSendComplete(const Comm::ConnectionPointer &conn, char *, size_t size, Comm::Flag errflag, int xerrno, void *data)
{
    GopherStateData *gopherState = (GopherStateData *) data;
    StoreEntry *entry = gopherState->entry;
    debugs(10, 5, HERE << conn << " size: " << size << " errflag: " << errflag);

    if (size > 0) {
        fd_bytes(conn->fd, size, FD_WRITE);
        statCounter.server.all.kbytes_out += size;
        statCounter.server.other.kbytes_out += size;
    }

    if (!entry->isAccepting()) {
        debugs(10, 3, "terminating due to bad " << *entry);
        // TODO: Do not abuse connection for triggering cleanup.
        gopherState->serverConn->close();
        return;
    }

    if (errflag) {
        const auto err = new ErrorState(ERR_WRITE_ERROR, Http::scServiceUnavailable, gopherState->fwd->request, gopherState->fwd->al);
        err->xerrno = xerrno;
        err->port = gopherState->fwd->request->url.port();
        err->url = xstrdup(entry->url());
        gopherState->fwd->fail(err);
        gopherState->serverConn->close();
        return;
    }

    /*
     * OK. We successfully reach remote site.  Start MIME typing
     * stuff.  Do it anyway even though request is not HTML type.
     */
    entry->buffer();

    gopherMimeCreate(gopherState);

    switch (gopherState->type_id) {

    case GOPHER_DIRECTORY:
        /* we got to convert it first */
        gopherState->conversion = GopherStateData::HTML_DIR;
        gopherState->HTML_header_added = 0;
        break;

    case GOPHER_INDEX:
        /* we got to convert it first */
        gopherState->conversion = GopherStateData::HTML_INDEX_RESULT;
        gopherState->HTML_header_added = 0;
        break;

    case GOPHER_CSO:
        /* we got to convert it first */
        gopherState->conversion = GopherStateData::HTML_CSO_RESULT;
        gopherState->cso_recno = 0;
        gopherState->HTML_header_added = 0;
        break;

    default:
        gopherState->conversion = GopherStateData::NORMAL;
        entry->flush();
    }

    /* Schedule read reply. */
    AsyncCall::Pointer call =  commCbCall(5,5, "gopherReadReply",
                                          CommIoCbPtrFun(gopherReadReply, gopherState));
    entry->delayAwareRead(conn, gopherState->replybuf, BUFSIZ, call);
}

/**
 * This will be called when connect completes. Write request.
 */
static void
gopherSendRequest(int, void *data)
{
    GopherStateData *gopherState = (GopherStateData *)data;
    MemBuf mb;
    mb.init();

    if (gopherState->type_id == GOPHER_CSO) {
        const char *t = strchr(gopherState->request, '?');

        if (t)
            ++t;        /* skip the ? */
        else
            t = "";

        mb.appendf("query %s\r\nquit", t);
    } else {
        if (gopherState->type_id == GOPHER_INDEX) {
            if (char *t = strchr(gopherState->request, '?'))
                *t = '\t';
        }
        mb.append(gopherState->request, strlen(gopherState->request));
    }
    mb.append("\r\n", 2);

    debugs(10, 5, gopherState->serverConn);
    AsyncCall::Pointer call = commCbCall(5,5, "gopherSendComplete",
                                         CommIoCbPtrFun(gopherSendComplete, gopherState));
    Comm::Write(gopherState->serverConn, &mb, call);

    if (!gopherState->entry->makePublic())
        gopherState->entry->makePrivate(true);
}

void
gopherStart(FwdState * fwd)
{
    GopherStateData *gopherState = new GopherStateData(fwd);

    debugs(10, 3, gopherState->entry->url());

    ++ statCounter.server.all.requests;

    ++ statCounter.server.other.requests;

    /* Parse url. */
    gopher_request_parse(fwd->request,
                         &gopherState->type_id, gopherState->request);

    comm_add_close_handler(fwd->serverConnection()->fd, gopherStateFree, gopherState);

    if (((gopherState->type_id == GOPHER_INDEX) || (gopherState->type_id == GOPHER_CSO))
            && (strchr(gopherState->request, '?') == NULL)) {
        /* Index URL without query word */
        /* We have to generate search page back to client. No need for connection */
        gopherMimeCreate(gopherState);

        if (gopherState->type_id == GOPHER_INDEX) {
            gopherState->conversion = GopherStateData::HTML_INDEX_PAGE;
        } else {
            if (gopherState->type_id == GOPHER_CSO) {
                gopherState->conversion = GopherStateData::HTML_CSO_PAGE;
            } else {
                gopherState->conversion = GopherStateData::HTML_INDEX_PAGE;
            }
        }

        gopherToHTML(gopherState, (char *) NULL, 0);
        fwd->markStoredReplyAsWhole("gopher instant internal request satisfaction");
        fwd->complete();
        return;
    }

    // XXX: Sharing open Connection with FwdState that has its own handlers/etc.
    gopherState->serverConn = fwd->serverConnection();
    gopherSendRequest(fwd->serverConnection()->fd, gopherState);
    AsyncCall::Pointer timeoutCall = commCbCall(5, 4, "gopherTimeout",
                                     CommTimeoutCbPtrFun(gopherTimeout, gopherState));
    commSetConnTimeout(fwd->serverConnection(), Config.Timeout.read, timeoutCall);
}

