
/*
 * $Id: errorpage.cc,v 1.129 1998/05/02 06:41:58 wessels Exp $
 *
 * DEBUG: section 4     Error Generation
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Abstract:  These routines are used to generate error messages to be
 *              sent to clients.  The error type is used to select between
 *              the various message formats. (formats are stored in the
 *              Config.errorDirectory)
 */

#include "squid.h"


/* local types */

typedef struct {
    int id;
    char *page_name;
} ErrorDynamicPageInfo;

/* local constant and vars */

/*
 * note: hard coded error messages are not appended with %S automagically
 * to give you more control on the format
 */
static const struct {
    int type;			/* and page_id */
    const char *text;
} error_hard_text[] = {

    {
	ERR_SQUID_SIGNATURE,
	    "\n<br clear=\"all\">\n"
	    "<hr noshade size=1>\n"
	    "Generated %T by %h (<a href=\"http://squid.nlanr.net/Squid/\">%s</a>)\n"
	    "</BODY></HTML>\n"
    }
};

static Stack ErrorDynamicPages;

/* local prototypes */

static const int error_hard_text_count = sizeof(error_hard_text) / sizeof(*error_hard_text);
static char **error_text = NULL;
static int error_page_count = 0;

static char *errorTryLoadText(const char *page_name, const char *dir);
static char *errorLoadText(const char *page_name);
static const char *errorFindHardText(err_type type);
static MemBuf errorBuildContent(ErrorState * err);
static const char *errorConvert(char token, ErrorState * err);
static CWCB errorSendComplete;

/*
 * Function:  errorInitialize
 *
 * Abstract:  This function finds the error messages formats, and stores
 *            them in error_text[];
 *
 * Global effects:
 *            error_text[] - is modified
 */
void
errorInitialize(void)
{
    int i;
    const char *text;
    error_page_count = ERR_MAX + ErrorDynamicPages.count;
    error_text = xcalloc(error_page_count, sizeof(char *));
    for (i = ERR_NONE + 1; i < error_page_count; i++) {
	safe_free(error_text[i]);
	/* hard-coded ? */
	if ((text = errorFindHardText(i)))
	    error_text[i] = xstrdup(text);
	else
	    /* precompiled ? */
	if (i < ERR_MAX)
	    error_text[i] = errorLoadText(err_type_str[i]);
	/* dynamic */
	else {
	    ErrorDynamicPageInfo *info = ErrorDynamicPages.items[i - ERR_MAX];
	    assert(info && info->id == i && info->page_name);
	    error_text[i] = errorLoadText(info->page_name);
	}
	assert(error_text[i]);
    }
}

static const char *
errorFindHardText(err_type type)
{
    int i;
    for (i = 0; i < error_hard_text_count; i++)
	if (error_hard_text[i].type == type)
	    return error_hard_text[i].text;
    return NULL;
}


static char *
errorLoadText(const char *page_name)
{
    /* test configured location */
    char *text = errorTryLoadText(page_name, Config.errorDirectory);
    /* test default location if failed */
    if (!text && strcmp(Config.errorDirectory, DEFAULT_SQUID_ERROR_DIR))
	text = errorTryLoadText(page_name, DEFAULT_SQUID_ERROR_DIR);
    /* giving up if failed */
    if (!text)
	fatal("failed to find or read error text file.");
    return text;
}

static char *
errorTryLoadText(const char *page_name, const char *dir)
{
    int fd;
    char path[MAXPATHLEN];
    struct stat sb;
    char *text;

    snprintf(path, MAXPATHLEN, "%s/%s",
	dir, page_name);
    fd = file_open(path, O_RDONLY, NULL, NULL, NULL);
    if (fd < 0 || fstat(fd, &sb) < 0) {
	debug(4, 0) ("errorTryLoadText: '%s': %s\n", path, xstrerror());
	if (fd >= 0)
	    file_close(fd);
	return NULL;
    }
    text = xcalloc(sb.st_size + 2 + 1, 1);	/* 2 == space for %S */
    if (read(fd, text, sb.st_size) != sb.st_size) {
	debug(4, 0) ("errorTryLoadText: failed to fully read: '%s': %s\n",
	    path, xstrerror());
	xfree(text);
	text = NULL;
    }
    file_close(fd);
    strcat(text, "%S");		/* add signature */
    return text;
}

static ErrorDynamicPageInfo *
errorDynamicPageInfoCreate(int id, const char *page_name)
{
    ErrorDynamicPageInfo *info = xcalloc(1, sizeof(ErrorDynamicPageInfo));
    info->id = id;
    info->page_name = xstrdup(page_name);
    return info;
}

static void
errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info)
{
    assert(info);
    xfree(info->page_name);
    xfree(info);
}

int
errorReservePageId(const char *page_name)
{
    ErrorDynamicPageInfo *info =
    errorDynamicPageInfoCreate(ERR_MAX + ErrorDynamicPages.count, page_name);
    stackPush(&ErrorDynamicPages, info);
    return info->id;
}

void
errorFree(void)
{
    int i;
    for (i = ERR_NONE + 1; i < error_page_count; i++)
	safe_free(error_text[i]);
    while (ErrorDynamicPages.count)
	errorDynamicPageInfoDestroy(stackPop(&ErrorDynamicPages));
    safe_free(error_text);
    error_page_count = 0;
}

/*
 * Function:  errorCon
 *
 * Abstract:  This function creates a ErrorState object.
 */
ErrorState *
errorCon(int type, http_status status)
{
    ErrorState *err = xcalloc(1, sizeof(ErrorState));
    err->page_id = type;	/* has to be reset manually if needed */
    err->type = type;
    err->http_status = status;
    return err;
}

/*
 * Function:  errorAppendEntry
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then stores the text in the specified store
 *            entry.  This function should only be called by ``server
 *            side routines'' which need to communicate errors to the
 *            client side.  It should also be called from client_side.c
 *            because we now support persistent connections, and
 *            cannot assume that we can immediately write to the socket
 *            for an error.
 */
void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
    HttpReply *rep;
    MemObject *mem = entry->mem_obj;
#if 0
    /*
     *  Kostas sez PUT "success" replies might not be STORE_PENDING?
     */
    assert(entry->store_status == STORE_PENDING);
#endif
    assert(mem != NULL);
    assert(mem->inmem_hi == 0);
    storeBuffer(entry);
    rep = errorBuildReply(err);
    httpReplySwapOut(rep, entry);
    httpReplyDestroy(rep);
    mem->reply->sline.status = err->http_status;
    storeBufferFlush(entry);
    storeComplete(entry);
    storeNegativeCache(entry);
    storeReleaseRequest(entry);
    errorStateFree(err);
}

/*
 * Function:  errorSend
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then sends it to the client.
 *            The callback function errorSendComplete() is called after
 *            the page has been written to the client socket (fd).
 *            errorSendComplete() deallocates 'err'.  We need to add
 *            'err' to the cbdata because comm_write() requires it
 *            for all callback data pointers.
 *
 *            Note, normally errorSend() should only be called from
 *            routines in ssl.c and pass.c, where we don't have any
 *            StoreEntry's.  In client_side.c we must allocate a StoreEntry
 *            for errors and use errorAppendEntry() to account for
 *            persistent/pipeline connections.
 */
void
errorSend(int fd, ErrorState * err)
{
    HttpReply *rep;
    debug(4, 3) ("errorSend: FD %d, err=%p\n", fd, err);
    assert(fd >= 0);
    /*
     * ugh, this is how we make sure error codes get back to
     * the client side for logging and error tracking.
     */
    if (err->request)
	err->request->err_type = err->type;
    /* moved in front of errorBuildBuf @?@ */
    EBIT_SET(err->flags, ERR_FLAG_CBDATA);
    cbdataAdd(err, MEM_NONE);
    rep = errorBuildReply(err);
    comm_write_mbuf(fd, httpReplyPack(rep), errorSendComplete, err);
    httpReplyDestroy(rep);
}

/*
 * Function:  errorSendComplete
 *
 * Abstract:  Called by commHandleWrite() after data has been written
 *            to the client socket.
 *
 * Note:      If there is a callback, the callback is responsible for
 *            closeing the FD, otherwise we do it ourseves.
 */
static void
errorSendComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    ErrorState *err = data;
    debug(4, 3) ("errorSendComplete: FD %d, size=%d\n", fd, size);
    if (errflag != COMM_ERR_CLOSING) {
	if (err->callback)
	    err->callback(fd, err->callback_data, size);
	else
	    comm_close(fd);
    }
    errorStateFree(err);
}

void
errorStateFree(ErrorState * err)
{
    requestUnlink(err->request);
    safe_free(err->redirect_url);
    safe_free(err->url);
    safe_free(err->host);
    safe_free(err->dnsserver_msg);
    safe_free(err->request_hdrs);
    if (EBIT_TEST(err->flags, ERR_FLAG_CBDATA))
	cbdataFree(err);
    else
	safe_free(err);
}

#define CVT_BUF_SZ 512

/*
 * B - URL with FTP %2f hack                    x
 * c - Squid error code                         x
 * d - seconds elapsed since request received   x
 * e - errno                                    x
 * E - strerror()                               x
 * f - FTP request line                         x
 * F - FTP reply line                           x
 * g - FTP server message                       x
 * h - cache hostname                           x
 * H - server host name                         x
 * i - client IP address                        x
 * I - server IP address                        x
 * L - HREF link for more info/contact          x
 * M - Request Method                           x
 * p - URL port #                               x
 * P - Protocol                                 x
 * R - Full HTTP Request                        x
 * S - squid signature from ERR_SIGNATURE       x
 * s - caching proxy software with version      x
 * t - local time                               x
 * T - UTC                                      x
 * U - URL without password                     x
 * u - URL without password, %2f added to path  x
 * w - cachemgr email address                   x
 * z - dns server error message                 x
 */

static const char *
errorConvert(char token, ErrorState * err)
{
    request_t *r = err->request;
    static char buf[CVT_BUF_SZ];
    const char *p = buf;
    switch (token) {
    case 'B':
	p = r ? ftpUrlWith2f(r) : "[no URL]";
	break;
    case 'e':
	snprintf(buf, CVT_BUF_SZ, "%d", err->xerrno);
	break;
    case 'E':
	if (err->xerrno)
	    snprintf(buf, CVT_BUF_SZ, "(%d) %s", err->xerrno, strerror(err->xerrno));
	else
	    snprintf(buf, CVT_BUF_SZ, "[No Error]");
	break;
    case 'f':
	/* FTP REQUEST LINE */
	if (err->ftp.request)
	    p = err->ftp.request;
	else
	    p = "<none>";
	break;
    case 'F':
	/* FTP REPLY LINE */
	if (err->ftp.request)
	    p = err->ftp.reply;
	else
	    p = "<none>";
	break;
    case 'g':
	/* FTP SERVER MESSAGE */
	p = wordlistCat(err->ftp_server_msg);
	break;
    case 'h':
	snprintf(buf, CVT_BUF_SZ, "%s", getMyHostname());
	break;
    case 'H':
	p = r ? r->host : "[unknown host]";
	break;
    case 'i':
	snprintf(buf, CVT_BUF_SZ, "%s", inet_ntoa(err->src_addr));
	break;
    case 'I':
	if (err->host) {
	    snprintf(buf, CVT_BUF_SZ, "%s", err->host);
	} else
	    p = "[unknown]";
	break;
    case 'L':
	if (Config.errHtmlText) {
	    snprintf(buf, CVT_BUF_SZ, "%s", Config.errHtmlText);
	} else
	    p = "[not available]";
	break;
    case 'M':
	p = r ? RequestMethodStr[r->method] : "[unkown method]";
	break;
    case 'p':
	if (r) {
	    snprintf(buf, CVT_BUF_SZ, "%d", (int) r->port);
	} else {
	    p = "[unknown port]";
	}
	break;
    case 'P':
	p = r ? ProtocolStr[r->protocol] : "[unkown protocol]";
	break;
    case 'R':
	p = err->request_hdrs ? err->request_hdrs : "[no request]";
	break;
    case 's':
	p = full_appname_string;
	break;
    case 'S':
	/* signature may contain %-escapes, recursion */
	if (err->page_id != ERR_SQUID_SIGNATURE) {
	    const int saved_id = err->page_id;
	    MemBuf mb;
	    err->page_id = ERR_SQUID_SIGNATURE;
	    mb = errorBuildContent(err);
	    snprintf(buf, CVT_BUF_SZ, "%s", mb.buf);
	    memBufClean(&mb);
	    err->page_id = saved_id;
	} else {
	    /* wow, somebody put %S into ERR_SIGNATURE, stop recursion */
	    p = "[%S]";
	}
	break;
    case 't':
	xstrncpy(buf, mkhttpdlogtime(&squid_curtime), 128);
	break;
    case 'T':
	snprintf(buf, CVT_BUF_SZ, "%s", mkrfc1123(squid_curtime));
	break;
    case 'U':
	p = r ? urlCanonicalClean(r) : err->url ? err->url : "[no URL]";
	break;
    case 'w':
	if (Config.adminEmail) {
	    snprintf(buf, CVT_BUF_SZ, "%s", Config.adminEmail);
	} else
	    p = "[unknown]";
	break;
    case 'z':
	if (err->dnsserver_msg)
	    p = err->dnsserver_msg;
	else
	    p = "[unknown]";
	break;
    case '%':
	p = "%";
	break;
    default:
	p = "%UNKNOWN%";
	break;
    }
    assert(p != NULL);
    debug(4, 3) ("errorConvert: %%%c --> '%s'\n", token, p);
    return p;
}

/* allocates and initializes an error response */
HttpReply *
errorBuildReply(ErrorState * err)
{
    HttpReply *rep = httpReplyCreate();
    MemBuf content = errorBuildContent(err);
    /* no LMT for error pages; error pages expire immediately */
    httpReplySetHeaders(rep, 1.0, err->http_status, NULL, "text/html", content.size, 0, squid_curtime);
    httpBodySet(&rep->body, content.buf, content.size + 1, NULL);
    memBufClean(&content);
    return rep;
}

static MemBuf
errorBuildContent(ErrorState * err)
{
    MemBuf content;
    const char *m;
    const char *p;
    const char *t;
    assert(err != NULL);
    assert(err->page_id > ERR_NONE && err->page_id < error_page_count);
    memBufDefInit(&content);
    m = error_text[err->page_id];
    assert(m);
    while ((p = strchr(m, '%'))) {
	memBufAppend(&content, m, p - m);	/* copy */
	t = errorConvert(*++p, err);	/* convert */
	memBufPrintf(&content, "%s", t);	/* copy */
	m = p + 1;		/* advance */
    }
    if (*m)
	memBufPrintf(&content, "%s", m);	/* copy tail */
    assert(content.size == strlen(content.buf));
    return content;
}
