
/*
 * $Id: errorpage.cc,v 1.95 1997/10/30 02:40:58 wessels Exp $
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
 * Abstract:	These routines are used to generate error messages to be
 *		sent to clients.  The error type is used to select between
 *		the various message formats. (formats are stored in the
 *		Config.errorDirectory)
 */

#include "squid.h"

static const char *err_string[] =
{
    "ERR_NONE",
    "ERR_READ_TIMEOUT",
    "ERR_LIFETIME_EXP",
    "ERR_READ_ERROR",
    "ERR_WRITE_ERROR",
    "ERR_CLIENT_ABORT",
    "ERR_CONNECT_FAIL",
    "ERR_INVALID_REQ",
    "ERR_UNSUP_REQ",
    "ERR_INVALID_URL",
    "ERR_SOCKET_FAILURE",
    "ERR_DNS_FAIL",
    "ERR_CANNOT_FORWARD",
    "ERR_NO_RELAY",
    "ERR_ZERO_SIZE_OBJECT",
    "ERR_FTP_DISABLED",
    "ERR_FTP_FAILURE",
    "ERR_ACCESS_DENIED",
    "ERR_MAX"
};

static char *error_text[ERR_MAX];

static void errorStateFree(ErrorState * err);
static const char *errorConvert(char token, ErrorState * err);
static const char *errorBuildBuf(ErrorState * err, int *len);
static CWCB errorSendComplete;

/*
 * Function:  errorInitialize
 *
 * Abstract:  This function reads in the error messages formats, and stores
 *            them in error_text[];
 *
 * Global effects:
 *            error_text[] - is modified
 */
void
errorInitialize(void)
{
    err_type i;
    int fd;
    char path[MAXPATHLEN];
    struct stat sb;
    assert(sizeof(err_string) == (ERR_MAX + 1) * sizeof(char *));
    for (i = ERR_NONE + 1; i < ERR_MAX; i++) {
	snprintf(path, MAXPATHLEN, "%s/%s",
	    Config.errorDirectory, err_string[i]);
	fd = file_open(path, O_RDONLY, NULL, NULL);
	if (fd < 0) {
	    debug(4, 0) ("errorInitialize: %s: %s\n", path, xstrerror());
	    fatal("Failed to open error text file");
	}
	if (fstat(fd, &sb) < 0)
	    fatal("fstat() failed on error text file");
	safe_free(error_text[i]);
	error_text[i] = xcalloc(sb.st_size + 1, 1);
	if (read(fd, error_text[i], sb.st_size) != sb.st_size)
	    fatal("failed to fully read error text file");
	file_close(fd);
    }
}

/*
 * Function:  errorCon
 *
 * Abstract:  This function creates a ErrorState object.
 */
ErrorState *
errorCon(err_type type, http_status status)
{
    ErrorState *err = xcalloc(1, sizeof(ErrorState));
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
 *            by 'err' and then attaches it to the specified 'entry'
 *
 * Note:      The above abstract is should be check for correctness!!!!
 */
void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
    const char *buf;
    MemObject *mem = entry->mem_obj;
    int len;
    assert(entry->store_status == STORE_PENDING);
    buf = errorBuildBuf(err, &len);
    storeAppend(entry, buf, len);
    if (mem)
	mem->reply->code = err->http_status;
    errorStateFree(err);
    xfree(err);
}

/*
 * Function:  errorSend
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then sends it to the client.
 *
 * Note:      The callback function errorSendComplete() cleans up 'err'
 *
 * Note:      I don't think we need to add 'err' to the callback table
 *            since the only path ends up a errorSendComplete().
 */
void
errorSend(int fd, ErrorState * err)
{
    const char *buf;
    int len;
    debug(4, 3) ("errorSend: FD %d, err=%p\n", fd, err);
    assert(fd >= 0);
    buf = errorBuildBuf(err, &len);
    cbdataAdd(err);
    comm_write(fd, xstrdup(buf), len, errorSendComplete, err, xfree);
}

/*
 * Function:  errorSendComplete
 *
 * Abstract:  This function 
 *
 * Note:      If there is a callback, the callback is responsible for
 *            closeing the FD, otherwise we do it ourseves.
 */
static void
errorSendComplete(int fd, char *buf, int size, int errflag, void *data)
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
    cbdataFree(err);
}

static void
errorStateFree(ErrorState * err)
{
    requestUnlink(err->request);
    safe_free(err->redirect_url);
    safe_free(err->url);
    safe_free(err->host);
    safe_free(err->dnsserver_msg);
    if (BIT_TEST(err->flags, ERR_FLAG_CBDATA))
	cbdataFree(err);
    else
	safe_free(err);
}

#define CVT_BUF_SZ 512

/*
 * c - Squid error code
 * d - seconds elapsed since request received
 * e - errno                                    x
 * E - strerror()                               x
 * F - FTP reply line                           x
 * f - FTP request line                         x
 * h - cache hostname                           x
 * i - client IP address                        x
 * I - server IP address                        x
 * L - HREF link for more info/contact          x
 * M - Request Method                           x
 * p - URL port #                               x
 * P - Protocol                                 x
 * t - local time                               x
 * T - UTC                                      x
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
    case 'e':
	snprintf(buf, CVT_BUF_SZ, "%d", err->xerrno);
	break;
    case 'E':
	snprintf(buf, CVT_BUF_SZ, "(%d) %s", err->xerrno, strerror(err->xerrno));
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
    case 't':
	xstrncpy(buf, mkhttpdlogtime(&squid_curtime), 128);
	break;
    case 'T':
	snprintf(buf, CVT_BUF_SZ, "%s", mkrfc1123(squid_curtime));
	break;
    case 'U':
	p = r ? urlCanonicalClean(r) : err->url;
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
    default:
	p = "%UNKNOWN%";
	break;
    }
    if (p == NULL)
	p = "<NULL>";
    debug(4, 3) ("errorConvert: %%%c --> '%s'\n", token, p);
    return p;
}

static const char *
errorBuildBuf(ErrorState * err, int *len)
{
    LOCAL_ARRAY(char, buf, ERROR_BUF_SZ);
    LOCAL_ARRAY(char, content, ERROR_BUF_SZ);
    char *hdr;
    int clen;
    int tlen;
    char *m;
    char *mx;
    char *p;
    const char *t;
    assert(err != NULL);
    assert(err->type > ERR_NONE && err->type < ERR_MAX);
    mx = m = xstrdup(error_text[err->type]);
    clen = 0;
    while ((p = strchr(m, '%'))) {
	*p = '\0';		/* terminate */
	xstrncpy(content + clen, m, ERROR_BUF_SZ - clen);	/* copy */
	clen += (p - m);	/* advance */
	if (clen >= ERROR_BUF_SZ)
	    break;
	p++;
	m = p + 1;
	t = errorConvert(*p, err);	/* convert */
	xstrncpy(content + clen, t, ERROR_BUF_SZ - clen);	/* copy */
	clen += strlen(t);	/* advance */
	if (clen >= ERROR_BUF_SZ)
	    break;
    }
    if (clen < ERROR_BUF_SZ && m != NULL) {
	xstrncpy(content + clen, m, ERROR_BUF_SZ - clen);
	clen += strlen(m);
    }
    if (clen >= ERROR_BUF_SZ) {
	clen = ERROR_BUF_SZ - 1;
	*(content + clen) = '\0';
    }
    assert(clen == strlen(content));
    hdr = httpReplyHeader((double) 1.0,
	err->http_status,
	"text/html",
	clen,
	0,			/* no LMT for error pages */
	squid_curtime);
    tlen = snprintf(buf, ERROR_BUF_SZ, "%s\r\n%s", hdr, content);
    if (len)
	*len = tlen;
    xfree(mx);
    return buf;
}
