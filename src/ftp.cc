
/*
 * $Id: ftp.cc,v 1.117 1997/06/02 17:19:25 wessels Exp $
 *
 * DEBUG: section 9     File Transfer Protocol (FTP)
 * AUTHOR: Harvest Derived
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

#include "squid.h"

#define FTP_DELETE_GAP  (1<<18)

enum {
    FTP_ISDIR,
    FTP_PASV_SUPPORTED,
    FTP_SKIP_WHITESPACE,
    FTP_REST_SUPPORTED,
    FTP_PASV_ONLY,
    FTP_AUTHENTICATED,
    FTP_IP_LOOKUP_PENDING,
    FTP_HTTP_HEADER_SENT,
    FTP_TRIED_NLST,
    FTP_USE_BASE,
    FTP_ROOT_DIR,
    FTP_HTML_HEADER_SENT
};

static const char *const crlf = "\r\n";
static char cbuf[1024];

typedef enum {
    BEGIN,
    SENT_USER,
    SENT_PASS,
    SENT_TYPE,
    SENT_MDTM,
    SENT_SIZE,
    SENT_PORT,
    SENT_PASV,
    SENT_CWD,
    SENT_LIST,
    SENT_NLST,
    SENT_REST,
    SENT_RETR,
    SENT_QUIT,
    READING_DATA
} ftp_state_t;

typedef struct _Ftpdata {
    StoreEntry *entry;
    request_t *request;
    char user[MAX_URL];
    char password[MAX_URL];
    char *reply_hdr;
    int reply_hdr_state;
    char *title_url;
    int conn_att;
    int login_att;
    ftp_state_t state;
    char *errmsg;
    time_t mdtm;
    int size;
    int flags;
    wordlist *pathcomps;
    char *filepath;
    int restart_offset;
    int rest_att;
    char *proxy_host;
    size_t list_width;
    wordlist *cwd_message;
    struct {
	int fd;
	char *buf;
	size_t size;
	off_t offset;
	FREE *freefunc;
	wordlist *message;
	char *last_message;
	int replycode;
    } ctrl;
    struct {
	int fd;
	char *buf;
	size_t size;
	off_t offset;
	FREE *freefunc;
    } data;
} FtpStateData;

typedef struct {
    char type;
    int size;
    char *date;
    char *name;
    char *showname;
    char *link;
} ftpListParts;

typedef void (FTPSM) _PARAMS((FtpStateData *));

/* Local functions */
static CNCB ftpConnectDone;
static CNCB ftpPasvCallback;
static IPH ftpConnect;
static PF ftpReadData;
static PF ftpStateFree;
static PF ftpTimeout;
static PF ftpReadControlReply;
static CWCB ftpWriteCommandCallback;
static char *ftpGetBasicAuth _PARAMS((const char *));
static void ftpLoginParser _PARAMS((const char *, FtpStateData *));
static void ftpFail _PARAMS((FtpStateData * ftpState));
static wordlist *ftpParseControlReply _PARAMS((char *buf, size_t len, int *code));
static void ftpSendPasv _PARAMS((FtpStateData * ftpState));
static void ftpSendCwd _PARAMS((FtpStateData * ftpState));
static void ftpSendPort _PARAMS((FtpStateData * ftpState));
static void ftpRestOrList _PARAMS((FtpStateData * ftpState));
static void ftpReadQuit _PARAMS((FtpStateData * ftpState));
static void ftpDataTransferDone _PARAMS((FtpStateData * ftpState));
static void ftpAppendSuccessHeader _PARAMS((FtpStateData * ftpState));
static STABH ftpAbort;

static FTPSM ftpReadWelcome;
static FTPSM ftpReadUser;
static FTPSM ftpReadPass;
static FTPSM ftpReadType;
static FTPSM ftpReadMdtm;
static FTPSM ftpReadSize;
static FTPSM ftpReadPort;
static FTPSM ftpReadPasv;
static FTPSM ftpReadCwd;
static FTPSM ftpReadList;
static FTPSM ftpReadRest;
static FTPSM ftpReadRetr;
static FTPSM ftpReadTransferDone;

FTPSM *FTP_SM_FUNCS[] =
{
    ftpReadWelcome,
    ftpReadUser,
    ftpReadPass,
    ftpReadType,
    ftpReadMdtm,
    ftpReadSize,
    ftpReadPort,
    ftpReadPasv,
    ftpReadCwd,
    ftpReadList,		/* SENT_LIST */
    ftpReadList,		/* SENT_NLST */
    ftpReadRest,
    ftpReadRetr,
    ftpReadQuit,
    ftpReadTransferDone
};

static void
ftpStateFree(int fd, void *data)
{
    FtpStateData *ftpState = data;
    if (ftpState == NULL)
	return;
    storeUnlockObject(ftpState->entry);
    storeUnregisterAbort(ftpState->entry);
    if (ftpState->reply_hdr) {
	put_free_8k_page(ftpState->reply_hdr);
	ftpState->reply_hdr = NULL;
    }
    requestUnlink(ftpState->request);
    if (ftpState->ctrl.buf)
	ftpState->ctrl.freefunc(ftpState->ctrl.buf);
    if (ftpState->data.buf)
	ftpState->data.freefunc(ftpState->data.buf);
    if (ftpState->pathcomps)
	wordlistDestroy(&ftpState->pathcomps);
    if (ftpState->ctrl.message)
	wordlistDestroy(&ftpState->ctrl.message);
    if (ftpState->cwd_message)
	wordlistDestroy(&ftpState->cwd_message);
    safe_free(ftpState->ctrl.last_message);
    safe_free(ftpState->title_url);
    safe_free(ftpState->filepath);
    xfree(ftpState);
}

static void
ftpLoginParser(const char *login, FtpStateData * ftpState)
{
    char *s = NULL;
    xstrncpy(ftpState->user, login, MAX_URL);
    if ((s = strchr(ftpState->user, ':'))) {
	*s = 0;
	xstrncpy(ftpState->password, s + 1, MAX_URL);
    } else {
	xstrncpy(ftpState->password, null_string, MAX_URL);
    }
    if (ftpState->user[0] || ftpState->password[0])
	return;
    xstrncpy(ftpState->user, "anonymous", MAX_URL);
    xstrncpy(ftpState->password, Config.Ftp.anon_user, MAX_URL);
}

static void
ftpTimeout(int fd, void *data)
{
    FtpStateData *ftpState = data;
    StoreEntry *entry = ftpState->entry;
    debug(9, 4, "ftpLifeTimeExpire: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    if (ftpState->data.fd >= 0)
	comm_close(ftpState->data.fd);
    comm_close(ftpState->ctrl.fd);
}

static void
ftpListingStart(FtpStateData * ftpState)
{
    StoreEntry *e = ftpState->entry;
    wordlist *w;
    storeAppendPrintf(e, "<!-- HTML listing generated by Squid %s -->\n",
	version_string);
    storeAppendPrintf(e, "<!-- %s -->\n", mkrfc1123(squid_curtime));
    storeAppendPrintf(e, "<HTML><HEAD><TITLE>\n");
    storeAppendPrintf(e, "FTP Directory: %s\n",
	ftpState->title_url);
    storeAppendPrintf(e, "</TITLE>\n");
    if (EBIT_TEST(ftpState->flags, FTP_USE_BASE))
	storeAppendPrintf(e, "<BASE HREF=\"%s\">\n",
	    rfc1738_escape(ftpState->title_url));
    storeAppendPrintf(e, "</HEAD><BODY>\n");
    if (ftpState->cwd_message) {
	storeAppendPrintf(e, "<PRE>\n");
	for (w = ftpState->cwd_message; w; w = w->next)
	    storeAppendPrintf(e, "%s\n", w->key);
	storeAppendPrintf(e, "</PRE>\n");
	storeAppendPrintf(e, "<HR>\n");
	wordlistDestroy(&ftpState->cwd_message);
    }
    storeAppendPrintf(e, "<H2>\n");
    storeAppendPrintf(e, "FTP Directory: %s\n", ftpState->title_url);
    storeAppendPrintf(e, "</H2>\n");
    storeAppendPrintf(e, "<PRE>\n");
    EBIT_SET(ftpState->flags, FTP_HTML_HEADER_SENT);
}

static void
ftpListingFinish(FtpStateData * ftpState)
{
    StoreEntry *e = ftpState->entry;
    storeAppendPrintf(e, "</PRE>\n");
    storeAppendPrintf(e, "<HR>\n");
    storeAppendPrintf(e, "<ADDRESS>\n");
    storeAppendPrintf(e, "Generated %s, by %s/%s@%s\n",
	mkrfc1123(squid_curtime),
	appname,
	version_string,
	getMyHostname());
    storeAppendPrintf(e, "</ADDRESS></BODY></HTML>\n");
}

static const char *Month[] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static int
is_month(const char *buf)
{
    int i;
    for (i = 0; i < 12; i++)
	if (!strcasecmp(buf, Month[i]))
	    return 1;
    return 0;
}


static void
ftpListPartsFree(ftpListParts ** parts)
{
    safe_free((*parts)->date);
    safe_free((*parts)->name);
    safe_free((*parts)->showname);
    safe_free((*parts)->link);
    safe_free(*parts);
}

#define MAX_TOKENS 64

static ftpListParts *
ftpListParseParts(const char *buf, int flags)
{
    ftpListParts *p = NULL;
    char *t = NULL;
    const char *ct = NULL;
    char *tokens[MAX_TOKENS];
    int i;
    int n_tokens;
    static char sbuf[128];
    char *xbuf = NULL;
    if (buf == NULL)
	return NULL;
    if (*buf == '\0')
	return NULL;
    p = xcalloc(1, sizeof(ftpListParts));
    n_tokens = 0;
    for (i = 0; i < MAX_TOKENS; i++)
	tokens[i] = (char *) NULL;
    xbuf = xstrdup(buf);
    for (t = strtok(xbuf, w_space); t && n_tokens < MAX_TOKENS; t = strtok(NULL, w_space))
	tokens[n_tokens++] = xstrdup(t);
    xfree(xbuf);
    /* locate the Month field */
    for (i = 3; i < n_tokens - 3; i++) {
	if (!is_month(tokens[i]))	/* Month */
	    continue;
	if (!sscanf(tokens[i - 1], "%[0-9]", sbuf))	/* Size */
	    continue;
	if (!sscanf(tokens[i + 1], "%[0-9]", sbuf))	/* Day */
	    continue;
	if (!sscanf(tokens[i + 2], "%[0-9:]", sbuf))	/* Yr | hh:mm */
	    continue;
	p->type = *tokens[0];
	p->size = atoi(tokens[i - 1]);
	sprintf(sbuf, "%s %2s %5s",
	    tokens[i], tokens[i + 1], tokens[i + 2]);
	if (!strstr(buf, sbuf))
	    sprintf(sbuf, "%s %2s %-5s",
		tokens[i], tokens[i + 1], tokens[i + 2]);
	if ((t = strstr(buf, sbuf))) {
	    p->date = xstrdup(sbuf);
	    if (BIT_TEST(flags, FTP_SKIP_WHITESPACE)) {
		t += strlen(sbuf);
		while (strchr(w_space, *t))
		    t++;
	    } else {
		/* XXX assumes a single space between date and filename
		 * suggested by:  Nathan.Bailey@cc.monash.edu.au and
		 * Mike Battersby <mike@starbug.bofh.asn.au> */
		t += strlen(sbuf) + 1;
	    }
	    p->name = xstrdup(t);
	    if ((t = strstr(p->name, " -> "))) {
		*t = '\0';
		p->link = xstrdup(t + 4);
	    }
	}
	break;
    }
    /* try it as a DOS listing */
    if (n_tokens > 3 && p->name == NULL &&
	sscanf(tokens[0], "%[0-9]-%[0-9]-%[0-9]", sbuf, sbuf, sbuf) == 3 &&
    /* 04-05-70 */
	sscanf(tokens[1], "%[0-9]:%[0-9]%[AaPp]%[Mm]", sbuf, sbuf, sbuf, sbuf) == 4) {
	/* 09:33PM */
	if (!strcasecmp(tokens[2], "<dir>")) {
	    p->type = 'd';
	} else {
	    p->type = '-';
	    p->size = atoi(tokens[2]);
	}
	sprintf(sbuf, "%s %s", tokens[0], tokens[1]);
	p->date = xstrdup(sbuf);
	p->name = xstrdup(tokens[3]);
    }
    /* Try EPLF format; carson@lehman.com */
    if (p->name == NULL && buf[0] == '+') {
	ct = buf + 1;
	p->type = 0;
	while (ct && *ct) {
	    switch (*ct) {
	    case '\t':
		sscanf(ct + 1, "%[^,]", sbuf);
		p->name = xstrdup(sbuf);
		break;
	    case 's':
		sscanf(ct + 1, "%d", &(p->size));
		break;
	    case 'm':
		sscanf(ct + 1, "%d", &i);
		p->date = xstrdup(ctime((time_t *) & i));
		*(strstr(p->date, "\n")) = '\0';
		break;
	    case '/':
		p->type = 'd';
		break;
	    case 'r':
		p->type = '-';
		break;
	    case 'i':
		break;
	    default:
		break;
	    }
	    ct = strstr(ct, ",");
	    if (ct) {
		ct++;
	    }
	}
	if (p->type == 0) {
	    p->type = '-';
	}
    }
    for (i = 0; i < n_tokens; i++)
	xfree(tokens[i]);
    if (p->name == NULL)
	ftpListPartsFree(&p);
    return p;
}

static const char *
dots_fill(size_t len)
{
    static char buf[256];
    int i = 0;
    if (len > Config.Ftp.list_width) {
	memset(buf, ' ', 256);
	buf[0] = '\n';
	buf[Config.Ftp.list_width + 4] = '\0';
	return buf;
    }
    for (i = (int) len; i < Config.Ftp.list_width; i++)
	buf[i - len] = (i % 2) ? '.' : ' ';
    buf[i - len] = '\0';
    return buf;
}

static char *
ftpHtmlifyListEntry(char *line, int flags)
{
    LOCAL_ARRAY(char, link, 2048);
    LOCAL_ARRAY(char, icon, 2048);
    LOCAL_ARRAY(char, html, 8192);
    char *ename = NULL;
    size_t width = Config.Ftp.list_width;
    ftpListParts *parts;
    /* check .. as special case */
    if (!strcmp(line, "..")) {
	sprintf(icon, "<IMG BORDER=0 SRC=\"%s%s%s\" ALT=\"%-6s\">",
	    Config.Ftp.icon_prefix,
	    "gopher-menu",
	    Config.Ftp.icon_suffix,
	    "[DIR]");
	sprintf(link, "<A HREF=\"%s\">%s</A>", "../", "Parent Directory");
	sprintf(html, "%s %s\n", icon, link);
	return html;
    }
    if (strlen(line) > 1024) {
	sprintf(html, "%s\n", line);
	return html;
    }
    if ((parts = ftpListParseParts(line, flags)) == NULL) {
	sprintf(html, "%s\n", line);
	return html;
    }
    if (!strcmp(parts->name, ".") || !strcmp(parts->name, "..")) {
	*html = '\0';
	ftpListPartsFree(&parts);
	return html;
    }
    parts->size += 1023;
    parts->size >>= 10;
    parts->showname = xstrdup(parts->name);
    if (!Config.Ftp.list_wrap) {
	if (strlen(parts->showname) > width - 1) {
	    *(parts->showname + width - 1) = '>';
	    *(parts->showname + width - 0) = '\0';
	}
    }
    ename = xstrdup(rfc1738_escape(parts->name));
    switch (parts->type) {
    case 'd':
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    Config.Ftp.icon_prefix,
	    "menu",
	    Config.Ftp.icon_suffix,
	    "[DIR]");
	sprintf(link, "<A HREF=\"%s/\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s]\n",
	    icon,
	    link,
	    parts->date);
	break;
    case 'l':
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    Config.Ftp.icon_prefix,
	    mimeGetIcon(parts->link),
	    Config.Ftp.icon_suffix,
	    "[LINK]");
	sprintf(link, "<A HREF=\"%s\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s]\n",
	    icon,
	    link,
	    parts->date);
	break;
    case '-':
    default:
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    Config.Ftp.icon_prefix,
	    mimeGetIcon(parts->name),
	    Config.Ftp.icon_suffix,
	    "[FILE]");
	sprintf(link, "<A HREF=\"%s\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s] %6dk\n",
	    icon,
	    link,
	    parts->date,
	    parts->size);
	break;
    }
    ftpListPartsFree(&parts);
    xfree(ename);
    return html;
}

static void
ftpParseListing(FtpStateData * ftpState, int len)
{
    char *buf = ftpState->data.buf;
    char *end;
    char *line;
    char *s;
    char *t;
    size_t linelen;
    size_t usable;
    StoreEntry *e = ftpState->entry;
    len += ftpState->data.offset;
    end = buf + len - 1;
    while (*end != '\r' && *end != '\n' && end > buf)
	end--;
    usable = end - buf;
    if (usable == 0) {
	debug(9, 1, "ftpParseListing: didn't find end for %s\n", e->url);
	return;
    }
    line = get_free_4k_page();
    end++;
    for (s = buf; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
	linelen = strcspn(s, crlf) + 1;
	if (linelen > 4096)
	    linelen = 4096;
	xstrncpy(line, s, linelen);
	debug(9, 7, "%s\n", line);
	if (!strncmp(line, "total", 5))
	    continue;
	t = ftpHtmlifyListEntry(line, ftpState->flags);
	assert(t != NULL);
	storeAppend(e, t, strlen(t));
    }
    assert(usable <= len);
    if (usable < len) {
	/* must copy partial line to beginning of buf */
	linelen = len - usable + 1;
	assert(linelen > 0);
	if (linelen > 4096)
	    linelen = 4096;
	xstrncpy(line, end, linelen);
	xstrncpy(ftpState->data.buf, line, ftpState->data.size);
	ftpState->data.offset = strlen(ftpState->data.buf);
    }
    put_free_4k_page(line);
}

static void
ftpReadData(int fd, void *data)
{
    FtpStateData *ftpState = data;
    int len;
    int clen;
    int off;
    int bin;
    StoreEntry *entry = ftpState->entry;
    assert(fd == ftpState->data.fd);
    if (protoAbortFetch(entry)) {
        squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
        ftpDataTransferDone(ftpState);
        return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->e_current_len;
    off = storeGetLowestReaderOffset(entry);
    if ((clen - off) > FTP_DELETE_GAP) {
	IOStats.Ftp.reads_deferred++;
	debug(9, 3, "ftpReadData: Read deferred for Object: %s\n",
	    entry->url);
	commSetSelect(fd, COMM_SELECT_READ, ftpReadData, data, 0);
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    commSetTimeout(fd, Config.Timeout.defer, NULL, NULL);
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    if (EBIT_TEST(ftpState->flags, FTP_ISDIR))
	if (!EBIT_TEST(ftpState->flags, FTP_HTML_HEADER_SENT))
	    ftpListingStart(ftpState);
    errno = 0;
    memset(ftpState->data.buf + ftpState->data.offset, '\0',
	ftpState->data.size - ftpState->data.offset);
    len = read(fd,
	ftpState->data.buf + ftpState->data.offset,
	ftpState->data.size - ftpState->data.offset);
    fd_bytes(fd, len, FD_READ);
    debug(9, 5, "ftpReadData: FD %d, Read %d bytes\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Ftp.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Ftp.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1, "ftpReadData: read error: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd, COMM_SELECT_READ,
		ftpReadData, data, 0);
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    ftpDataTransferDone(ftpState);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	ftpDataTransferDone(ftpState);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	if (EBIT_TEST(ftpState->flags, FTP_HTML_HEADER_SENT))
	    ftpListingFinish(ftpState);
	storeTimestampsSet(entry);
	storeComplete(entry);
	ftpDataTransferDone(ftpState);
    } else {
	if (EBIT_TEST(ftpState->flags, FTP_ISDIR)) {
	    ftpParseListing(ftpState, len);
	} else {
	    assert(ftpState->data.offset == 0);
	    storeAppend(entry, ftpState->data.buf, len);
	}
	commSetSelect(fd, COMM_SELECT_READ, ftpReadData, data, 0);
    }
}

static char *
ftpGetBasicAuth(const char *req_hdr)
{
    char *auth_hdr;
    char *t;
    if (req_hdr == NULL)
	return NULL;
    if ((auth_hdr = mime_get_header(req_hdr, "Authorization")) == NULL)
	return NULL;
    if ((t = strtok(auth_hdr, " \t")) == NULL)
	return NULL;
    if (strcasecmp(t, "Basic") != 0)
	return NULL;
    if ((t = strtok(NULL, " \t")) == NULL)
	return NULL;
    return base64_decode(t);
}

/*
 * ftpCheckAuth
 *
 * Return 1 if we have everything needed to complete this request.
 * Return 0 if something is missing.
 */
static int
ftpCheckAuth(FtpStateData * ftpState, char *req_hdr)
{
    char *orig_user;
    char *auth;
    ftpLoginParser(ftpState->request->login, ftpState);
    if (ftpState->user[0] && ftpState->password[0])
	return 1;		/* name and passwd both in URL */
    if (!ftpState->user[0] && !ftpState->password[0])
	return 1;		/* no name or passwd */
    if (ftpState->password[0])
	return 1;		/* passwd with no name? */
    /* URL has name, but no passwd */
    if ((auth = ftpGetBasicAuth(req_hdr)) == NULL)
	return 0;		/* need auth header */
    orig_user = xstrdup(ftpState->user);
    ftpLoginParser(auth, ftpState);
    if (!strcmp(orig_user, ftpState->user)) {
	xfree(orig_user);
	return 1;		/* same username */
    }
    strcpy(ftpState->user, orig_user);
    xfree(orig_user);
    return 0;			/* different username */
}

static void
ftpCleanupUrlpath(FtpStateData * ftpState)
{
    request_t *request = ftpState->request;
    int again;
    int l;
    char *t = NULL;
    char *s = NULL;
    do {
	again = 0;
	l = strlen(request->urlpath);
	/* check for null path */
	if (*request->urlpath == '\0') {
	    xstrncpy(request->urlpath, ".", MAX_URL);
	    EBIT_SET(ftpState->flags, FTP_ROOT_DIR);
	    again = 1;
	} else if ((l >= 1) && (*(request->urlpath + l - 1) == '/')) {
	    /* remove any trailing slashes from path */
	    *(request->urlpath + l - 1) = '\0';
	    EBIT_SET(ftpState->flags, FTP_ISDIR);
	    EBIT_RESET(ftpState->flags, FTP_USE_BASE);
	    again = 1;
	} else if ((l >= 2) && (!strcmp(request->urlpath + l - 2, "/."))) {
	    /* remove trailing /. */
	    *(request->urlpath + l - 2) = '\0';
	    EBIT_SET(ftpState->flags, FTP_ISDIR);
	    EBIT_RESET(ftpState->flags, FTP_USE_BASE);
	    again = 1;
	} else if (*request->urlpath == '/') {
	    /* remove any leading slashes from path */
	    t = xstrdup(request->urlpath + 1);
	    xstrncpy(request->urlpath, t, MAX_URL);
	    xfree(t);
	    again = 1;
	} else if (!strncmp(request->urlpath, "./", 2)) {
	    /* remove leading ./ */
	    t = xstrdup(request->urlpath + 2);
	    xstrncpy(request->urlpath, t, MAX_URL);
	    xfree(t);
	    again = 1;
	} else if ((t = strstr(request->urlpath, "/./"))) {
	    /* remove /./ */
	    s = xstrdup(t + 2);
	    xstrncpy(t, s, strlen(s));
	    xfree(s);
	    again = 1;
	} else if ((t = strstr(request->urlpath, "//"))) {
	    /* remove // */
	    s = xstrdup(t + 1);
	    xstrncpy(t, s, strlen(s));
	    xfree(s);
	    again = 1;
	}
    } while (again);
}


static void
ftpBuildTitleUrl(FtpStateData * ftpState)
{
    request_t *request = ftpState->request;
    size_t len;
    char *t;
    len = 64
	+ strlen(ftpState->user)
	+ strlen(ftpState->password)
	+ strlen(request->host)
	+ strlen(request->urlpath);
    t = ftpState->title_url = xcalloc(len, 1);
    strcat(t, "ftp://");
    if (strcmp(ftpState->user, "anonymous")) {
	strcat(t, ftpState->user);
	strcat(t, "@");
    }
    strcat(t, request->host);
    if (request->port != urlDefaultPort(PROTO_FTP))
	sprintf(&t[strlen(t)], ":%d", request->port);
    strcat(t, "/");
    if (!EBIT_TEST(ftpState->flags, FTP_ROOT_DIR))
	strcat(t, request->urlpath);
}


void
ftpStart(request_t * request, StoreEntry * entry)
{
    LOCAL_ARRAY(char, realm, 8192);
    char *url = entry->url;
    FtpStateData *ftpState = xcalloc(1, sizeof(FtpStateData));
    char *response;
    int fd;
    debug(9, 3, "FtpStart: '%s'\n", entry->url);
    storeLockObject(entry);
    ftpState->entry = entry;
    ftpState->request = requestLink(request);
    ftpState->ctrl.fd = -1;
    ftpState->data.fd = -1;
    EBIT_SET(ftpState->flags, FTP_PASV_SUPPORTED);
    EBIT_SET(ftpState->flags, FTP_REST_SUPPORTED);
    if (!ftpCheckAuth(ftpState, request->headers)) {
	/* This request is not fully authenticated */
	if (request->port == 21) {
	    sprintf(realm, "ftp %s", ftpState->user);
	} else {
	    sprintf(realm, "ftp %s port %d",
		ftpState->user, request->port);
	}
	response = authorization_needed_msg(request, realm);
	storeAppend(entry, response, strlen(response));
	httpParseReplyHeaders(response, entry->mem_obj->reply);
	storeComplete(entry);
	ftpStateFree(-1, ftpState);
	return;
    }
    ftpCleanupUrlpath(ftpState);
    ftpBuildTitleUrl(ftpState);
    debug(9, 5, "FtpStart: host=%s, path=%s, user=%s, passwd=%s\n",
	ftpState->request->host, ftpState->request->urlpath,
	ftpState->user, ftpState->password);
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (fd == COMM_ERROR) {
	debug(9, 4, "ftpStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return;
    }
    ftpState->ctrl.fd = fd;
    comm_add_close_handler(fd, ftpStateFree, ftpState);
    commSetTimeout(fd, Config.Timeout.connect, ftpTimeout, ftpState);
    storeRegisterAbort(entry, ftpAbort, ftpState);
    ipcache_nbgethostbyname(request->host, fd, ftpConnect, ftpState);
}

static void
ftpConnect(int fd, const ipcache_addrs * ia, void *data)
{
    FtpStateData *ftpState = data;
    request_t *request = ftpState->request;
    StoreEntry *entry = ftpState->entry;
    EBIT_RESET(ftpState->flags, FTP_IP_LOOKUP_PENDING);
    assert(fd == ftpState->ctrl.fd);
    if (ia == NULL) {
	debug(9, 4, "ftpConnect: Unknown host: %s\n", request->host);
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(fd);
	return;
    }
    debug(9, 3, "ftpConnect: %s is %s\n", request->host,
	inet_ntoa(ia->in_addrs[0]));
    /* Open connection. */
    commSetTimeout(fd, Config.Timeout.connect, ftpTimeout, ftpState);
    commConnectStart(ftpState->ctrl.fd,
	request->host,
	request->port,
	ftpConnectDone,
	ftpState);
}

static void
ftpConnectDone(int fd, int status, void *data)
{
    FtpStateData *ftpState = data;
    debug(9, 3, "ftpConnectDone\n");
    if (status == COMM_ERROR) {
	squid_error_entry(ftpState->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    ftpState->state = BEGIN;
    ftpState->ctrl.buf = get_free_4k_page();
    ftpState->ctrl.freefunc = put_free_4k_page;
    ftpState->ctrl.size = 4096;
    ftpState->ctrl.offset = 0;
    ftpState->data.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    ftpState->data.size = SQUID_TCP_SO_RCVBUF;
    ftpState->data.freefunc = xfree;
    commSetSelect(fd, COMM_SELECT_READ, ftpReadControlReply, ftpState, 0);
}

/* ====================================================================== */


static void
ftpWriteCommand(const char *buf, FtpStateData * ftpState)
{
    debug(9, 5, "ftpWriteCommand: %s\n", buf);
    comm_write(ftpState->ctrl.fd,
	xstrdup(buf),
	strlen(buf),
	ftpWriteCommandCallback,
	ftpState,
	xfree);
    commSetSelect(ftpState->ctrl.fd,
	COMM_SELECT_READ,
	ftpReadControlReply,
	ftpState,
	0);
}

static void
ftpWriteCommandCallback(int fd, char *buf, int size, int errflag, void *data)
{
    FtpStateData *ftpState = data;
    StoreEntry *entry = ftpState->entry;
    debug(9, 7, "ftpWriteCommandCallback: wrote %d bytes\n", size);
    if (errflag) {
	BIT_RESET(entry->flag, ENTRY_CACHABLE);
	storeReleaseRequest(entry);
	squid_error_entry(entry, ERR_WRITE_ERROR, xstrerror());
	comm_close(fd);
    }
}

static wordlist *
ftpParseControlReply(char *buf, size_t len, int *codep)
{
    char *s;
    int complete = 0;
    wordlist *head;
    wordlist *list;
    wordlist **tail = &head;
    off_t offset;
    size_t linelen;
    int code = -1;
    debug(9, 5, "ftpParseControlReply\n");
    if (*(buf + len - 1) != '\n')
	return NULL;
    for (s = buf; s - buf < len; s += strcspn(s, crlf), s += strspn(s, crlf)) {
	linelen = strcspn(s, crlf) + 1;
	if (linelen > 3)
	    complete = (*s >= '0' && *s <= '9' && *(s + 3) == ' ');
	if (complete)
	    code = atoi(s);
	offset = 0;
	if (linelen > 3)
	    if (*s >= '0' && *s <= '9' && (*(s + 3) == '-' || *(s + 3) == ' '))
		offset = 4;
	list = xcalloc(1, sizeof(wordlist));
	list->key = xmalloc(linelen - offset);
	xstrncpy(list->key, s + offset, linelen - offset);
	debug(9, 7, "%p: %s\n", list->key, list->key);
	*tail = list;
	tail = &list->next;
    }
    if (!complete)
	wordlistDestroy(&head);
    if (codep)
	*codep = code;
    return head;
}

static void
ftpReadControlReply(int fd, void *data)
{
    FtpStateData *ftpState = data;
    StoreEntry *entry = ftpState->entry;
    char *oldbuf;
    wordlist **W;
    int len;
    debug(9, 5, "ftpReadControlReply\n");
    assert(ftpState->ctrl.offset < ftpState->ctrl.size);
    len = read(fd,
	ftpState->ctrl.buf + ftpState->ctrl.offset,
	ftpState->ctrl.size - ftpState->ctrl.offset);
    fd_bytes(fd, len, FD_READ);
    debug(9, 5, "ftpReadControlReply: FD %d, Read %d bytes\n", fd, len);
    if (len > 0)
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
    if (len < 0) {
	debug(50, 1, "ftpReadControlReply: read error: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd,
		COMM_SELECT_READ,
		ftpReadControlReply,
		ftpState,
		0);
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
	return;
    }
    if (len == 0) {
	debug(9, 1, "Read 0 bytes from FTP control socket?\n");
	BIT_RESET(entry->flag, ENTRY_CACHABLE);
	storeReleaseRequest(entry);
	squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	comm_close(fd);
	return;
    }
    len += ftpState->ctrl.offset;
    ftpState->ctrl.offset = len;
    assert(len <= ftpState->ctrl.size);
    wordlistDestroy(&ftpState->ctrl.message);
    ftpState->ctrl.message = ftpParseControlReply(ftpState->ctrl.buf, len,
	&ftpState->ctrl.replycode);
    if (ftpState->ctrl.message == NULL) {
	debug(9, 5, "ftpReadControlReply: partial server reply\n");
	if (len == ftpState->ctrl.size) {
	    oldbuf = ftpState->ctrl.buf;
	    ftpState->ctrl.buf = xcalloc(ftpState->ctrl.size << 1, 1);
	    xmemcpy(ftpState->ctrl.buf, oldbuf, ftpState->ctrl.size);
	    ftpState->ctrl.size <<= 1;
	    ftpState->ctrl.freefunc(oldbuf);
	    ftpState->ctrl.freefunc = xfree;
	}
	commSetSelect(fd, COMM_SELECT_READ, ftpReadControlReply, ftpState, 0);
	return;
    }
    for (W = &ftpState->ctrl.message; *W && (*W)->next; W = &(*W)->next);
    safe_free(ftpState->ctrl.last_message);
    ftpState->ctrl.last_message = (*W)->key;
    safe_free(*W);
    ftpState->ctrl.offset = 0;
    FTP_SM_FUNCS[ftpState->state] (ftpState);
}

/* ====================================================================== */

static void
ftpReadWelcome(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "ftpReadWelcome\n");
    if (EBIT_TEST(ftpState->flags, FTP_PASV_ONLY))
	ftpState->login_att++;
    if (code == 220) {
	if (ftpState->ctrl.message)
	    if (strstr(ftpState->ctrl.message->key, "NetWare"))
		EBIT_SET(ftpState->flags, FTP_SKIP_WHITESPACE);
	if (ftpState->proxy_host != NULL)
	    sprintf(cbuf, "USER %s@%s\r\n",
		ftpState->user,
		ftpState->request->host);
	else
	    sprintf(cbuf, "USER %s\r\n", ftpState->user);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_USER;
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpReadUser(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "ftpReadUser\n");
    if (code == 230) {
	ftpReadPass(ftpState);
    } else if (code == 331) {
	sprintf(cbuf, "PASS %s\r\n", ftpState->password);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_PASS;
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpReadPass(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    char *t;
    char *filename;
    char mode;
    debug(9, 3, "ftpReadPass\n");
    if (code == 230) {
	t = strrchr(ftpState->request->urlpath, '/');
	filename = t ? t + 1 : ftpState->request->urlpath;
	mode = mimeGetTransferMode(filename);
	sprintf(cbuf, "TYPE %c\r\n", mode);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_TYPE;
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpReadType(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    wordlist *w;
    wordlist **T;
    char *path;
    char *d;
    debug(9, 3, "This is ftpReadType\n");
    if (code == 200) {
	if (EBIT_TEST(ftpState->flags, FTP_ROOT_DIR)) {
	    ftpSendPasv(ftpState);
	} else {
	    path = xstrdup(ftpState->request->urlpath);
	    T = &ftpState->pathcomps;
	    for (d = strtok(path, "/"); d; d = strtok(NULL, "/")) {
		w = xcalloc(1, sizeof(wordlist));
		w->key = xstrdup(d);
		*T = w;
		T = &w->next;
	    }
	    xfree(path);
	    ftpSendCwd(ftpState);
	}
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpSendCwd(FtpStateData * ftpState)
{
    wordlist *w;
    debug(9, 3, "ftpSendCwd\n");
    if ((w = ftpState->pathcomps) == NULL) {
	debug(9, 3, "the final component was a directory\n");
	EBIT_SET(ftpState->flags, FTP_ISDIR);
	if (!EBIT_TEST(ftpState->flags, FTP_ROOT_DIR))
	    strcat(ftpState->title_url, "/");
	ftpSendPasv(ftpState);
	return;
    }
    sprintf(cbuf, "CWD %s\r\n", w->key);
    ftpWriteCommand(cbuf, ftpState);
    ftpState->state = SENT_CWD;
}

static void
ftpReadCwd(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    size_t len = 0;
    wordlist *w;
    debug(9, 3, "This is ftpReadCwd\n");
    w = ftpState->pathcomps;
    assert(w != NULL);
    if (code >= 200 && code < 300) {
	if (ftpState->cwd_message)
	    wordlistDestroy(&ftpState->cwd_message);
	ftpState->cwd_message = ftpState->ctrl.message;
	ftpState->ctrl.message = NULL;
	/* CWD OK */
	ftpState->pathcomps = w->next;
	xfree(w->key);
	xfree(w);
	ftpSendCwd(ftpState);
    } else {
	/* CWD FAILED */
	while (w) {
	    len += (strlen(w->key) + 1);
	    w = w->next;
	}
	ftpState->filepath = xcalloc(len, 1);
	for (w = ftpState->pathcomps; w; w = w->next) {
	    strcat(ftpState->filepath, w->key);
	    if (w->next)
		strcat(ftpState->filepath, "/");
	}
	wordlistDestroy(&ftpState->pathcomps);
	assert(*ftpState->filepath != '\0');
	sprintf(cbuf, "MDTM %s\r\n", ftpState->filepath);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_MDTM;
    }
}

static void
ftpReadMdtm(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadMdtm\n");
    if (code == 213) {
	ftpState->mdtm = parse_iso3307_time(ftpState->ctrl.last_message);
	assert(ftpState->filepath != NULL);
	assert(*ftpState->filepath != '\0');
	sprintf(cbuf, "SIZE %s\r\n", ftpState->filepath);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_SIZE;
    } else if (code < 0) {
	ftpFail(ftpState);
    }
}

static void
ftpReadSize(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadSize\n");
    if (code == 213) {
	ftpState->size = atoi(ftpState->ctrl.last_message);
	ftpSendPasv(ftpState);
    } else if (code < 0) {
	ftpFail(ftpState);
    }
}

static void
ftpSendPasv(FtpStateData * ftpState)
{
    int fd;
    assert(ftpState->data.fd < 0);
    if (!EBIT_TEST(ftpState->flags, FTP_PASV_SUPPORTED)) {
	ftpSendPort(ftpState);
	return;
    }
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	ftpState->entry->url);
    if (fd < 0) {
	ftpFail(ftpState);
	return;
    }
    ftpState->data.fd = fd;
    commSetTimeout(fd, Config.Timeout.read, ftpTimeout, ftpState);
    sprintf(cbuf, "PASV\r\n");
    ftpWriteCommand(cbuf, ftpState);
    ftpState->state = SENT_PASV;
}

static void
ftpReadPasv(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    int h1, h2, h3, h4;
    int p1, p2;
    int n;
    u_short port;
    int fd = ftpState->data.fd;
    char *buf = ftpState->ctrl.last_message;
    LOCAL_ARRAY(char, junk, 1024);
    debug(9, 3, "This is ftpReadPasv\n");
    if (code != 227) {
	debug(9, 3, "PASV not supported by remote end\n");
	ftpSendPort(ftpState);
	return;
    }
    if (strlen(buf) > 1024) {
	debug(9, 1, "Avoiding potential buffer overflow\n");
	ftpSendPort(ftpState);
	return;
    }
    /*  227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).  */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    debug(9, 5, "scanning: %s\n", buf);
    n = sscanf(buf, "%[^0123456789]%d,%d,%d,%d,%d,%d",
	junk, &h1, &h2, &h3, &h4, &p1, &p2);
    if (n != 7 || p1 < 0 || p2 < 0 || p1 > 255 || p2 > 255) {
	debug(9, 3, "Bad 227 reply\n");
	debug(9, 3, "n=%d, p1=%d, p2=%d\n", n, p1, p2);
	ftpSendPort(ftpState);
	return;
    }
    sprintf(junk, "%d.%d.%d.%d", h1, h2, h3, h4);
    if (!safe_inet_addr(junk, NULL)) {
	debug(9, 1, "unsafe address (%s)\n", junk);
	ftpSendPort(ftpState);
	return;
    }
    port = ((p1 << 8) + p2);
    debug(9, 5, "ftpReadPasv: connecting to %s, port %d\n", junk, port);
    commConnectStart(fd, junk, port, ftpPasvCallback, ftpState);
}

static void
ftpPasvCallback(int fd, int status, void *data)
{
    FtpStateData *ftpState = data;
    debug(9, 3, "ftpPasvCallback\n");
    if (status == COMM_ERROR) {
	squid_error_entry(ftpState->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    ftpRestOrList(ftpState);
}

static void
ftpSendPort(FtpStateData * ftpState)
{
    debug(9, 3, "This is ftpSendPort\n");
    EBIT_RESET(ftpState->flags, FTP_PASV_SUPPORTED);
}

static void
ftpReadPort(FtpStateData * ftpState)
{
    debug(9, 3, "This is ftpReadPort\n");
}

static void
ftpRestOrList(FtpStateData * ftpState)
{
    debug(9, 3, "This is ftpRestOrList\n");
    if (EBIT_TEST(ftpState->flags, FTP_ISDIR)) {
	sprintf(cbuf, "LIST\r\n");
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_LIST;
    } else if (ftpState->restart_offset > 0) {
	sprintf(cbuf, "REST\r\n");
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_REST;
    } else {
	assert(ftpState->filepath != NULL);
	sprintf(cbuf, "RETR %s\r\n", ftpState->filepath);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_RETR;
    }
}

static void
ftpReadRest(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadRest\n");
    assert(ftpState->restart_offset > 0);
    if (code == 350) {
	assert(ftpState->filepath != NULL);
	sprintf(cbuf, "RETR %s\r\n", ftpState->filepath);
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_RETR;
    } else if (code > 0) {
	debug(9, 3, "ftpReadRest: REST not supported\n");
	EBIT_RESET(ftpState->flags, FTP_REST_SUPPORTED);
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpReadList(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadList\n");
    if (code == 150 || code == 125) {
	ftpAppendSuccessHeader(ftpState);
	commSetSelect(ftpState->data.fd,
	    COMM_SELECT_READ,
	    ftpReadData,
	    ftpState,
	    0);
	ftpState->state = READING_DATA;
	return;
    } else if (!EBIT_TEST(ftpState->flags, FTP_TRIED_NLST)) {
	EBIT_SET(ftpState->flags, FTP_TRIED_NLST);
	sprintf(cbuf, "NLST\r\n");
	ftpWriteCommand(cbuf, ftpState);
	ftpState->state = SENT_NLST;
    } else {
	ftpFail(ftpState);
	return;
    }
}

static void
ftpReadRetr(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadRetr\n");
    if (code >= 100 && code < 200) {
	debug(9, 3, "reading data channel\n");
	ftpAppendSuccessHeader(ftpState);
	commSetSelect(ftpState->data.fd,
	    COMM_SELECT_READ,
	    ftpReadData,
	    ftpState,
	    0);
	ftpState->state = READING_DATA;
    } else {
	ftpFail(ftpState);
    }
}

static void
ftpReadTransferDone(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    debug(9, 3, "This is ftpReadTransferDone\n");
    if (code != 226) {
	debug(9, 1, "Got code %d after reading data, releasing entry\n");
	storeReleaseRequest(ftpState->entry);
    }
}

static void
ftpDataTransferDone(FtpStateData * ftpState)
{
    debug(9, 3, "This is ftpDataTransferDone\n");
    if (ftpState->data.fd > -1) {
        comm_close(ftpState->data.fd);
        ftpState->data.fd = -1;
    }
    assert(ftpState->ctrl.fd > -1);
    sprintf(cbuf, "QUIT\r\n");
    ftpWriteCommand(cbuf, ftpState);
    ftpState->state = SENT_QUIT;
}

static void
ftpReadQuit(FtpStateData * ftpState)
{
    comm_close(ftpState->ctrl.fd);
}

static void
ftpFail(FtpStateData * ftpState)
{
    debug(9, 3, "ftpFail\n");
    comm_close(ftpState->ctrl.fd);
}

static void
ftpAppendSuccessHeader(FtpStateData * ftpState)
{
    char *mime_type = NULL;
    char *mime_enc = NULL;
    char *urlpath = ftpState->request->urlpath;
    char *filename = NULL;
    char *t = NULL;
    StoreEntry *e = ftpState->entry;
    struct _http_reply *reply = e->mem_obj->reply;
    if (EBIT_TEST(ftpState->flags, FTP_HTTP_HEADER_SENT))
	return;
    assert(e->mem_obj->e_current_len == 0);
    filename = (t = strrchr(urlpath, '/')) ? t + 1 : urlpath;
    if (EBIT_TEST(ftpState->flags, FTP_ISDIR)) {
	mime_type = "text/html";
    } else {
	mime_type = mimeGetContentType(filename);
	mime_enc = mimeGetContentEncoding(filename);
    }
    storeAppendPrintf(e, "HTTP/1.0 200 Gatewaying\r\n");
    reply->code = 200;
    reply->version = 1.0;
    storeAppendPrintf(e, "Date: %s\r\n", mkrfc1123(squid_curtime));
    reply->date = squid_curtime;
    storeAppendPrintf(e, "MIME-Version: 1.0\r\n");
    storeAppendPrintf(e, "Server: Squid %s\r\n", version_string);
    if (ftpState->size > 0) {
	storeAppendPrintf(e, "Content-Length: %d\r\n", ftpState->size);
        reply->content_length = ftpState->size;
    }
    if (mime_type) {
	storeAppendPrintf(e, "Content-Type: %s\r\n", mime_type);
    	xstrncpy(reply->content_type, mime_type, HTTP_REPLY_FIELD_SZ);
    }
    if (mime_enc)
	storeAppendPrintf(e, "Content-Encoding: %s\r\n", mime_enc);
    if (ftpState->mdtm > 0) {
	storeAppendPrintf(e, "Last-Modified: %s\r\n", mkrfc1123(ftpState->mdtm));
	reply->last_modified = ftpState->mdtm;
    }
    storeAppendPrintf(e, "\r\n");
    storeTimestampsSet(e);
    assert(e->flag & KEY_PRIVATE);
    storeSetPublicKey(e);
}

static void
ftpAbort(void *data)
{
    FtpStateData *ftpState = data;
    debug(9, 1, "ftpAbort: %s\n", ftpState->entry->url);
    ftpDataTransferDone(ftpState);
}
