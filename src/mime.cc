/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MIME Parsing and Internal Icons */

#include "squid.h"
#include "base/RegexPattern.h"
#include "debug/Messages.h"
#include "fde.h"
#include "fs_io.h"
#include "globals.h"
#include "HttpHdrCc.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "internal.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StoreClient.h"

#include <array>

#if HAVE_REGEX_H
#include <regex.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* forward declarations */
static void mimeFreeMemory(void);
static const SBuf mimeGetIcon(const char *fn);

class MimeIcon : public StoreClient
{
    MEMPROXY_CLASS(MimeIcon);

public:
    explicit MimeIcon(const char *aName);
    ~MimeIcon() override;
    void setName(char const *);
    SBuf getName() const;
    void load();

    /* StoreClient API */
    LogTags *loggingTags() const override { return nullptr; } // no access logging/ACLs
    void fillChecklist(ACLFilledChecklist &) const override;

private:
    SBuf icon_;
    char *url_;
};

class MimeEntry
{
    MEMPROXY_CLASS(MimeEntry);

public:
    explicit MimeEntry(const SBuf &aPattern,
                       const char *aContentType,
                       const char *aContentEncoding, const char *aTransferMode,
                       bool optionViewEnable, bool optionDownloadEnable,
                       const char *anIconName);
    ~MimeEntry();

    RegexPattern pattern;
    const char *content_type;
    const char *content_encoding;
    char transfer_mode;
    bool view_option;
    bool download_option;
    MimeIcon theIcon;
    MimeEntry *next;
};

static MimeEntry *MimeTable = nullptr;
static MimeEntry **MimeTableTail = &MimeTable;

static MimeEntry *
mimeGetEntry(const char *fn, int skip_encodings)
{
    MimeEntry *m;
    char *t;
    char *name = xstrdup(fn);

    do {
        t = nullptr;

        for (m = MimeTable; m; m = m->next) {
            if (m->pattern.match(name))
                break;
        }

        if (!skip_encodings)
            (void) 0;
        else if (m == nullptr)
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
                m = nullptr;
            }
        }
    } while (t);

    xfree(name);
    return m;
}

MimeIcon::MimeIcon(const char *aName) :
    url_(nullptr)
{
    setName(aName);
}

MimeIcon::~MimeIcon()
{
    xfree(url_);
}

void
MimeIcon::setName(char const *aString)
{
    xfree(url_);
    icon_ = aString;
    url_ = xstrdup(internalLocalUri("/squid-internal-static/icons/", icon_));
}

SBuf
MimeIcon::getName() const
{
    return icon_;
}

const SBuf
mimeGetIcon(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 1);

    if (!m || !m->theIcon.getName().cmp(dash_str))
        return SBuf();

    return m->theIcon.getName();
}

const char *
mimeGetIconURL(const char *fn)
{
    SBuf icon(mimeGetIcon(fn));

    if (icon.isEmpty())
        return null_string;

    if (Config.icons.use_short_names) {
        static SBuf mb;
        mb.clear();
        mb.append("/squid-internal-static/icons/");
        mb.append(icon);
        return mb.c_str();
    } else {
        return internalLocalUri("/squid-internal-static/icons/", icon);
    }
}

const char *
mimeGetContentType(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 1);

    if (m == nullptr)
        return nullptr;

    if (!strcmp(m->content_type, dash_str))
        return nullptr;

    return m->content_type;
}

const char *
mimeGetContentEncoding(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 0);

    if (m == nullptr)
        return nullptr;

    if (!strcmp(m->content_encoding, dash_str))
        return nullptr;

    return m->content_encoding;
}

char
mimeGetTransferMode(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 0);
    return m ? m->transfer_mode : 'I';
}

bool
mimeGetDownloadOption(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 1);
    return m ? m->download_option : 0;
}

bool
mimeGetViewOption(const char *fn)
{
    MimeEntry *m = mimeGetEntry(fn, 0);
    return m != nullptr ? m->view_option : false;
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
    char *icon;
    char *type;
    char *encoding;
    char *mode;
    char *option;
    int view_option;
    int download_option;
    MimeEntry *m;

    if (filename == nullptr)
        return;

    if ((fp = fopen(filename, "r")) == nullptr) {
        int xerrno = errno;
        debugs(25, DBG_IMPORTANT, "mimeInit: " << filename << ": " << xstrerr(xerrno));
        return;
    }

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    mimeFreeMemory();

    while (fgets(buf, BUFSIZ, fp)) {

        try {

            if ((t = strchr(buf, '#')))
                *t = '\0';

            if ((t = strchr(buf, '\r')))
                *t = '\0';

            if ((t = strchr(buf, '\n')))
                *t = '\0';

            if (buf[0] == '\0')
                continue;

            xstrncpy(chopbuf, buf, BUFSIZ);

            const auto pattern = SBuf(strtok(chopbuf, w_space));
            if (pattern.isEmpty()) {
                debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: parse failure: '" << buf << "'");
                continue;
            }

            if ((type = strtok(nullptr, w_space)) == nullptr) {
                debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: parse failure: '" << buf << "'");
                continue;
            }

            if ((icon = strtok(nullptr, w_space)) == nullptr) {
                debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: parse failure: '" << buf << "'");
                continue;
            }

            if ((encoding = strtok(nullptr, w_space)) == nullptr) {
                debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: parse failure: '" << buf << "'");
                continue;
            }

            if ((mode = strtok(nullptr, w_space)) == nullptr) {
                debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: parse failure: '" << buf << "'");
                continue;
            }

            download_option = 0;
            view_option = 0;

            while ((option = strtok(nullptr, w_space)) != nullptr) {
                if (!strcmp(option, "+download"))
                    download_option = 1;
                else if (!strcmp(option, "+view"))
                    view_option = 1;
                else
                    debugs(25, DBG_IMPORTANT, "ERROR: mimeInit: unknown option: '" << buf << "' (" << option << ")");
            }

            m = new MimeEntry(SBuf(pattern),type,encoding,mode,view_option,download_option,icon);

            *MimeTableTail = m;

            MimeTableTail = &m->next;

            debugs(25, 5, "mimeInit: added '" << buf << "'");

        } catch(...) {
            debugs(25, DBG_IMPORTANT, "ERROR: " << CurrentException);
            continue;
        }
    }

    fclose(fp);

    for (m = MimeTable; m != nullptr; m = m->next)
        m->theIcon.load();
    debugs(25, Important(28), "Finished loading MIME types and icons.");
}

void
mimeFreeMemory(void)
{
    MimeEntry *m;

    while ((m = MimeTable)) {
        MimeTable = m->next;
        delete m;
    }

    MimeTableTail = &MimeTable;
}

void
MimeIcon::load()
{
    const char *type = mimeGetContentType(icon_.c_str());

    if (type == nullptr)
        fatal("Unknown icon format while reading mime.conf\n");

    if (const auto e = storeGetPublic(url_, Http::METHOD_GET)) {
        // do not overwrite an already stored icon
        e->abandon(__FUNCTION__);
        return;
    }

    // XXX: if a 204 is cached due to earlier load 'failure' we should try to reload.

    // default is a 200 object with image data.
    // set to the backup value of 204 on image loading errors
    Http::StatusCode status = Http::scOkay;

    static char path[MAXPATHLEN];
    *path = 0;
    if (snprintf(path, sizeof(path)-1, "%s/" SQUIDSBUFPH, Config.icons.directory, SQUIDSBUFPRINT(icon_)) < 0) {
        debugs(25, DBG_CRITICAL, "ERROR: icon file '" << Config.icons.directory << "/" << icon_ << "' path is longer than " << MAXPATHLEN << " bytes");
        status = Http::scNoContent;
    }

    int fd = -1;
    errno = 0;
    if (status == Http::scOkay && (fd = file_open(path, O_RDONLY | O_BINARY)) < 0) {
        int xerrno = errno;
        debugs(25, DBG_CRITICAL, "ERROR: opening icon file " << path << ": " << xstrerr(xerrno));
        status = Http::scNoContent;
    }

    struct stat sb;
    errno = 0;
    if (status == Http::scOkay && fstat(fd, &sb) < 0) {
        int xerrno = errno;
        debugs(25, DBG_CRITICAL, "ERROR: opening icon file " << path << " FD " << fd << ", fstat error " << xstrerr(xerrno));
        file_close(fd);
        status = Http::scNoContent;
    }

    StoreEntry *e = storeCreatePureEntry(url_, url_, Http::METHOD_GET);
    e->lock("MimeIcon::created");
    EBIT_SET(e->flags, ENTRY_SPECIAL);
    const auto madePublic = e->setPublicKey();
    assert(madePublic); // nothing can block ENTRY_SPECIAL from becoming public

    /* fill `e` with a canned 2xx response object */

    const auto mx = MasterXaction::MakePortless<XactionInitiator::initIcon>();
    HttpRequestPointer r(HttpRequest::FromUrlXXX(url_, mx));
    if (!r)
        fatalf("mimeLoadIcon: cannot parse internal URL: %s", url_);

    e->buffer();

    e->mem_obj->request = r;

    HttpReplyPointer reply(new HttpReply);

    if (status == Http::scNoContent)
        reply->setHeaders(status, nullptr, nullptr, 0, -1, -1);
    else
        reply->setHeaders(status, nullptr, mimeGetContentType(icon_.c_str()), sb.st_size, sb.st_mtime, -1);
    reply->cache_control = new HttpHdrCc();
    reply->cache_control->maxAge(86400);
    reply->header.putCc(reply->cache_control);
    e->replaceHttpReply(reply.getRaw());

    if (status == Http::scOkay) {
        /* read the file into the buffer and append it to store */
        int n;
        std::array<char, 4096> buf;
        while ((n = FD_READ_METHOD(fd, buf.data(), buf.size())) > 0)
            e->append(buf.data(), n);

        file_close(fd);
    }

    e->flush();
    e->complete();
    e->timestampsSet();
    // MimeIcons are only loaded once, prevent accidental destruction
    // e->unlock("MimeIcon::created");
    debugs(25, 3, "Loaded icon " << url_);
}

void
MimeIcon::fillChecklist(ACLFilledChecklist &) const
{
    // Unreachable: We never mayInitiateCollapsing() or startCollapsingOn().
    assert(false);
}

MimeEntry::~MimeEntry()
{
    xfree(content_type);
    xfree(content_encoding);
}

MimeEntry::MimeEntry(const SBuf &aPattern,
                     const char *aContentType, const char *aContentEncoding,
                     const char *aTransferMode, bool optionViewEnable,
                     bool optionDownloadEnable, const char *anIconName) :
    pattern(aPattern, REG_EXTENDED|REG_NOSUB|REG_ICASE),
    content_type(xstrdup(aContentType)),
    content_encoding(xstrdup(aContentEncoding)),
    view_option(optionViewEnable),
    download_option(optionDownloadEnable),
    theIcon(anIconName), next(nullptr)
{
    if (!strcasecmp(aTransferMode, "ascii"))
        transfer_mode = 'A';
    else if (!strcasecmp(aTransferMode, "text"))
        transfer_mode = 'A';
    else
        transfer_mode = 'I';
}

