
/*
 * DEBUG: section 25    MIME Parsing and Internal Icons
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "disk.h"
#include "fde.h"
#include "globals.h"
#include "HttpHdrCc.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "internal.h"
#include "Mem.h"
#include "MemBuf.h"
#include "mime.h"
#include "MemObject.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StoreClient.h"

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#define GET_HDR_SZ 1024

/* forward declarations */
static void mimeFreeMemory(void);
static char const *mimeGetIcon(const char *fn);

class MimeIcon : public StoreClient
{

public:
    MimeIcon ();
    ~MimeIcon ();
    void setName (char const *);
    char const * getName () const;
    void _free();
    void load();
    void created (StoreEntry *newEntry);

private:
    char *icon;
    char *url;
};

class mimeEntry
{

public:
    void *operator new (size_t byteCount);
    void operator delete (void *address);

    char *pattern;
    regex_t compiled_pattern;
    char *icon;
    char *content_type;
    char *content_encoding;
    char transfer_mode;

    unsigned int view_option:1;
    unsigned int download_option:1;

    mimeEntry *next;
    MimeIcon theIcon;
};

static mimeEntry *MimeTable = NULL;
static mimeEntry **MimeTableTail = &MimeTable;

void *
mimeEntry::operator new (size_t byteCount)
{
    return xcalloc(1, byteCount);
}

void
mimeEntry::operator delete (void *address)
{
    safe_free (address);
}

static mimeEntry *
mimeGetEntry(const char *fn, int skip_encodings)
{
    mimeEntry *m;
    char *t;
    char *name = xstrdup(fn);

    do {
        t = NULL;

        for (m = MimeTable; m; m = m->next) {
            if (regexec(&m->compiled_pattern, name, 0, 0, 0) == 0)
                break;
        }

        if (!skip_encodings)
            (void) 0;
        else if (m == NULL)
            (void) 0;
        else if (strcmp(m->content_type, dash_str))
            (void) 0;
        else if (!strcmp(m->content_encoding, dash_str))
            (void) 0;
        else {
            /* Assume we matched /\.\w$/ and cut off the last extension */
            if ((t = strrchr(name, '.'))) {
                *t = '\0';
            } else {
                /* What? A encoding without a extension? */
                m = NULL;
            }
        }
    } while (t);

    xfree(name);
    return m;
}

MimeIcon::MimeIcon () : icon (NULL), url (NULL)
{}

MimeIcon::~MimeIcon ()
{
    _free();
}

void
MimeIcon::setName (char const *aString)
{
    safe_free (icon);
    safe_free (url);
    icon = xstrdup (aString);
    url = xstrdup (internalLocalUri("/squid-internal-static/icons/", icon));
}

char const *
MimeIcon::getName () const
{
    return icon;
}

void
MimeIcon::_free()
{
    safe_free (icon);
    safe_free (url);
}

char const *
mimeGetIcon(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 1);

    if (m == NULL)
        return NULL;

    if (!strcmp(m->theIcon.getName(), dash_str))
        return NULL;

    return m->theIcon.getName();
}

const char *
mimeGetIconURL(const char *fn)
{
    char const *icon = mimeGetIcon(fn);

    if (icon == NULL)
        return null_string;

    if (Config.icons.use_short_names) {
        static MemBuf mb;
        mb.reset();
        mb.Printf("/squid-internal-static/icons/%s", icon);
        return mb.content();
    } else {
        return internalLocalUri("/squid-internal-static/icons/", icon);
    }
}

char *
mimeGetContentType(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 1);

    if (m == NULL)
        return NULL;

    if (!strcmp(m->content_type, dash_str))
        return NULL;

    return m->content_type;
}

char *
mimeGetContentEncoding(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 0);

    if (m == NULL)
        return NULL;

    if (!strcmp(m->content_encoding, dash_str))
        return NULL;

    return m->content_encoding;
}

char
mimeGetTransferMode(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 0);
    return m ? m->transfer_mode : 'I';
}

int
mimeGetDownloadOption(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 1);
    return m ? m->download_option : 0;
}

int
mimeGetViewOption(const char *fn)
{
    mimeEntry *m = mimeGetEntry(fn, 0);
    return m ? m->view_option : 0;
}

/* Initializes/reloads the mime table
 * Note: Due to Solaris STDIO problems the caller should NOT
 * call mimeFreeMemory on reconfigure. This way, if STDIO
 * fails we at least have the old copy loaded.
 */
void
mimeInit(char *filename)
{
    FILE *fp;
    char buf[BUFSIZ];
    char chopbuf[BUFSIZ];
    char *t;
    char *pattern;
    char *icon;
    char *type;
    char *encoding;
    char *mode;
    char *option;
    int view_option;
    int download_option;
    regex_t re;
    mimeEntry *m;
    int re_flags = REG_EXTENDED | REG_NOSUB | REG_ICASE;

    if (filename == NULL)
        return;

    if ((fp = fopen(filename, "r")) == NULL) {
        debugs(25, DBG_IMPORTANT, "mimeInit: " << filename << ": " << xstrerror());
        return;
    }

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    mimeFreeMemory();

    while (fgets(buf, BUFSIZ, fp)) {
        if ((t = strchr(buf, '#')))
            *t = '\0';

        if ((t = strchr(buf, '\r')))
            *t = '\0';

        if ((t = strchr(buf, '\n')))
            *t = '\0';

        if (buf[0] == '\0')
            continue;

        xstrncpy(chopbuf, buf, BUFSIZ);

        if ((pattern = strtok(chopbuf, w_space)) == NULL) {
            debugs(25, DBG_IMPORTANT, "mimeInit: parse error: '" << buf << "'");
            continue;
        }

        if ((type = strtok(NULL, w_space)) == NULL) {
            debugs(25, DBG_IMPORTANT, "mimeInit: parse error: '" << buf << "'");
            continue;
        }

        if ((icon = strtok(NULL, w_space)) == NULL) {
            debugs(25, DBG_IMPORTANT, "mimeInit: parse error: '" << buf << "'");
            continue;
        }

        if ((encoding = strtok(NULL, w_space)) == NULL) {
            debugs(25, DBG_IMPORTANT, "mimeInit: parse error: '" << buf << "'");
            continue;
        }

        if ((mode = strtok(NULL, w_space)) == NULL) {
            debugs(25, DBG_IMPORTANT, "mimeInit: parse error: '" << buf << "'");
            continue;
        }

        download_option = 0;
        view_option = 0;

        while ((option = strtok(NULL, w_space)) != NULL) {
            if (!strcmp(option, "+download"))
                download_option = 1;
            else if (!strcmp(option, "+view"))
                view_option = 1;
            else
                debugs(25, DBG_IMPORTANT, "mimeInit: unknown option: '" << buf << "' (" << option << ")");
        }

        if (regcomp(&re, pattern, re_flags) != 0) {
            debugs(25, DBG_IMPORTANT, "mimeInit: regcomp error: '" << buf << "'");
            continue;
        }

        m = new mimeEntry;
        m->pattern = xstrdup(pattern);
        m->content_type = xstrdup(type);
        m->theIcon.setName(icon);
        m->content_encoding = xstrdup(encoding);
        m->compiled_pattern = re;

        if (!strcasecmp(mode, "ascii"))
            m->transfer_mode = 'A';
        else if (!strcasecmp(mode, "text"))
            m->transfer_mode = 'A';
        else
            m->transfer_mode = 'I';

        m->view_option = view_option;

        m->download_option = download_option;

        *MimeTableTail = m;

        MimeTableTail = &m->next;

        debugs(25, 5, "mimeInit: added '" << buf << "'");
    }

    fclose(fp);
    /*
     * Create Icon StoreEntry's
     */

    for (m = MimeTable; m != NULL; m = m->next)
        m->theIcon.load();

    debugs(25, DBG_IMPORTANT, "Loaded Icons.");
}

void
mimeFreeMemory(void)
{
    mimeEntry *m;

    while ((m = MimeTable)) {
        MimeTable = m->next;
        safe_free(m->pattern);
        safe_free(m->content_type);
        safe_free(m->icon);
        safe_free(m->content_encoding);
        regfree(&m->compiled_pattern);
        delete m;
    }

    MimeTableTail = &MimeTable;
}

void
MimeIcon::load()
{
    const char *type = mimeGetContentType(icon);

    if (type == NULL)
        fatal("Unknown icon format while reading mime.conf\n");

    StoreEntry::getPublic(this, url, METHOD_GET);
}

void
MimeIcon::created (StoreEntry *newEntry)
{
    /* is already in the store, do nothing */

    if (!newEntry->isNull())
        return;

    int fd;

    int n;

    RequestFlags flags;

    struct stat sb;

    LOCAL_ARRAY(char, path, MAXPATHLEN);

    char *buf;

    snprintf(path, MAXPATHLEN, "%s/%s", Config.icons.directory, icon);

    fd = file_open(path, O_RDONLY | O_BINARY);

    if (fd < 0) {
        debugs(25, DBG_CRITICAL, "mimeLoadIconFile: " << path << ": " << xstrerror());
        return;
    }

    if (fstat(fd, &sb) < 0) {
        debugs(25, DBG_CRITICAL, "mimeLoadIconFile: FD " << fd << ": fstat: " << xstrerror());
        file_close(fd);
        return;
    }

    flags.cachable = 1;
    StoreEntry *e = storeCreateEntry(url,
                                     url,
                                     flags,
                                     METHOD_GET);
    assert(e != NULL);
    EBIT_SET(e->flags, ENTRY_SPECIAL);
    e->setPublicKey();
    e->buffer();
    HttpRequest *r = HttpRequest::CreateFromUrl(url);

    if (NULL == r)
        fatal("mimeLoadIcon: cannot parse internal URL");

    e->mem_obj->request = HTTPMSGLOCK(r);

    HttpReply *reply = new HttpReply;

    reply->setHeaders(HTTP_OK, NULL, mimeGetContentType(icon), sb.st_size, sb.st_mtime, -1);

    reply->cache_control = new HttpHdrCc();

    reply->cache_control->maxAge(86400);

    reply->header.putCc(reply->cache_control);

    e->replaceHttpReply(reply);

    /* read the file into the buffer and append it to store */
    buf = (char *)memAllocate(MEM_4K_BUF);

    while ((n = FD_READ_METHOD(fd, buf, 4096)) > 0)
        e->append(buf, n);

    file_close(fd);

    e->flush();

    e->complete();

    e->timestampsSet();

    debugs(25, 3, "Loaded icon " << url);

    e->unlock();

    memFree(buf, MEM_4K_BUF);
}
