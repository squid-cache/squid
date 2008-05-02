
/*
 * $Id: cache_cf.cc,v 1.528.2.8 2008/03/04 12:10:00 amosjeffries Exp $
 *
 * DEBUG: section 3     Configuration File Parsing
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
#include "authenticate.h"
#include "AuthConfig.h"
#include "AuthScheme.h"
#include "CacheManager.h"
#include "Store.h"
#include "SwapDir.h"
#include "ConfigParser.h"
#include "ACL.h"
#include "StoreFileSystem.h"
#include "Parsing.h"
#include "MemBuf.h"
#include "wordlist.h"
#if HAVE_GLOB_H
#include <glob.h>
#endif

#if SQUID_SNMP
#include "snmp.h"
#endif
#if USE_SQUID_ESI
#include "ESIParser.h"
#endif

#if ICAP_CLIENT
#include "ICAP/ICAPConfig.h"

static void parse_icap_service_type(ICAPConfig *);
static void dump_icap_service_type(StoreEntry *, const char *, const ICAPConfig &);
static void free_icap_service_type(ICAPConfig *);
static void parse_icap_class_type(ICAPConfig *);
static void dump_icap_class_type(StoreEntry *, const char *, const ICAPConfig &);
static void free_icap_class_type(ICAPConfig *);
static void parse_icap_access_type(ICAPConfig *);
static void dump_icap_access_type(StoreEntry *, const char *, const ICAPConfig &);
static void free_icap_access_type(ICAPConfig *);

#endif

CBDATA_TYPE(peer);

static const char *const T_SECOND_STR = "second";
static const char *const T_MINUTE_STR = "minute";
static const char *const T_HOUR_STR = "hour";
static const char *const T_DAY_STR = "day";
static const char *const T_WEEK_STR = "week";
static const char *const T_FORTNIGHT_STR = "fortnight";
static const char *const T_MONTH_STR = "month";
static const char *const T_YEAR_STR = "year";
static const char *const T_DECADE_STR = "decade";

static const char *const B_BYTES_STR = "bytes";
static const char *const B_KBYTES_STR = "KB";
static const char *const B_MBYTES_STR = "MB";
static const char *const B_GBYTES_STR = "GB";

static const char *const list_sep = ", \t\n\r";

static void parse_logformat(logformat ** logformat_definitions);
static void parse_access_log(customlog ** customlog_definitions);
#if UNUSED_CODE
static int check_null_access_log(customlog *customlog_definitions);
#endif

static void dump_logformat(StoreEntry * entry, const char *name, logformat * definitions);
static void dump_access_log(StoreEntry * entry, const char *name, customlog * definitions);
static void free_logformat(logformat ** definitions);
static void free_access_log(customlog ** definitions);

static void update_maxobjsize(void);
static void configDoConfigure(void);
static void parse_refreshpattern(refresh_t **);
static int parseTimeUnits(const char *unit);
static void parseTimeLine(time_t * tptr, const char *units);
static void parse_ushort(u_short * var);
static void parse_string(char **);
static void default_all(void);
static void defaults_if_none(void);
static int parse_line(char *);
static void parseBytesLine(size_t * bptr, const char *units);
static size_t parseBytesUnits(const char *unit);
static void free_all(void);
void requirePathnameExists(const char *name, const char *path);
static OBJH dump_config;
#if HTTP_VIOLATIONS
static void dump_http_header_access(StoreEntry * entry, const char *name, header_mangler header[]);
static void parse_http_header_access(header_mangler header[]);
static void free_http_header_access(header_mangler header[]);
static void dump_http_header_replace(StoreEntry * entry, const char *name, header_mangler header[]);
static void parse_http_header_replace(header_mangler * header);
static void free_http_header_replace(header_mangler * header);
#endif
static void parse_denyinfo(acl_deny_info_list ** var);
static void dump_denyinfo(StoreEntry * entry, const char *name, acl_deny_info_list * var);
static void free_denyinfo(acl_deny_info_list ** var);

#if USE_WCCPv2
static void parse_sockaddr_in_list(sockaddr_in_list **);
static void dump_sockaddr_in_list(StoreEntry *, const char *, const sockaddr_in_list *);
static void free_sockaddr_in_list(sockaddr_in_list **);
#if CURRENTLY_UNUSED
static int check_null_sockaddr_in_list(const sockaddr_in_list *);
#endif /* CURRENTLY_UNUSED */
#endif /* USE_WCCPv2 */

static void parse_http_port_list(http_port_list **);
static void dump_http_port_list(StoreEntry *, const char *, const http_port_list *);
static void free_http_port_list(http_port_list **);

#if USE_SSL
static void parse_https_port_list(https_port_list **);
static void dump_https_port_list(StoreEntry *, const char *, const https_port_list *);
static void free_https_port_list(https_port_list **);
#if 0
static int check_null_https_port_list(const https_port_list *);
#endif
#endif /* USE_SSL */

static void parse_b_size_t(size_t * var);
static void parse_b_int64_t(int64_t * var);

static int parseOneConfigFile(const char *file_name, unsigned int depth);

/*
 * LegacyParser is a parser for legacy code that uses the global
 * approach.  This is static so that it is only exposed to cache_cf.
 * Other modules needing access to a ConfigParser should have it
 * provided to them in their parserFOO methods.
 */
static ConfigParser LegacyParser = ConfigParser();

void
self_destruct(void)
{
    LegacyParser.destruct();
}

static void
update_maxobjsize(void)
{
    int i;
    int64_t ms = -1;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        assert (Config.cacheSwap.swapDirs[i].getRaw());

        if (dynamic_cast<SwapDir *>(Config.cacheSwap.swapDirs[i].getRaw())->
                max_objsize > ms)
            ms = dynamic_cast<SwapDir *>(Config.cacheSwap.swapDirs[i].getRaw())->max_objsize;
    }
    store_maxobjsize = ms;
}

static void
SetConfigFilename(char const *file_name, bool is_pipe)
{
    cfg_filename = file_name;

    char const *token;

    if (is_pipe)
        cfg_filename = file_name + 1;
    else if ((token = strrchr(cfg_filename, '/')))
        cfg_filename = token + 1;
}

static const char*
skip_ws(const char* s)
{
    while (xisspace(*s))
        ++s;

    return s;
}

static int
parseManyConfigFiles(char* files, int depth)
{
    int error_count = 0;
    char* saveptr = NULL;
#if HAVE_GLOB
    char *path;
    glob_t globbuf;
    int i;
    memset(&globbuf, 0, sizeof(globbuf));
    for (path = strwordtok(files, &saveptr); path; path = strwordtok(NULL, &saveptr)) {
	if (glob(path, globbuf.gl_pathc ? GLOB_APPEND : 0, NULL, &globbuf) != 0) {
	    fatalf("Unable to find configuration file: %s: %s",
		path, xstrerror());
	}
     }
    for (i = 0; i < (int)globbuf.gl_pathc; i++) {
	error_count += parseOneConfigFile(globbuf.gl_pathv[i], depth);
    }
    globfree(&globbuf);
#else
    char* file = strwordtok(files, &saveptr);
    while (file != NULL) {
	error_count += parseOneConfigFile(file, depth);
	file = strwordtok(NULL, &saveptr);
    }
#endif /* HAVE_GLOB */
    return error_count;
}

static int
parseOneConfigFile(const char *file_name, unsigned int depth)
{
    FILE *fp = NULL;
    const char *orig_cfg_filename = cfg_filename;
    const int orig_config_lineno = config_lineno;
    char *token = NULL;
    char *tmp_line = NULL;
    int tmp_line_len = 0;
    int err_count = 0;
    int is_pipe = 0;

    debugs(3, 1, "Processing Configuration File: " << file_name << " (depth " << depth << ")");
    if (depth > 16) {
        fatalf("WARNING: can't include %s: includes are nested too deeply (>16)!\n", file_name);
        return 1;
    }

    if (file_name[0] == '!' || file_name[0] == '|') {
        fp = popen(file_name + 1, "r");
        is_pipe = 1;
    } else {
        fp = fopen(file_name, "r");
    }

    if (fp == NULL)
        fatalf("Unable to open configuration file: %s: %s", file_name, xstrerror());

#ifdef _SQUID_WIN32_

    setmode(fileno(fp), O_TEXT);

#endif

    SetConfigFilename(file_name, bool(is_pipe));

    memset(config_input_line, '\0', BUFSIZ);

    config_lineno = 0;

    while (fgets(config_input_line, BUFSIZ, fp)) {
        config_lineno++;

        if ((token = strchr(config_input_line, '\n')))
            *token = '\0';

        if ((token = strchr(config_input_line, '\r')))
            *token = '\0';

        if (strncmp(config_input_line, "#line ", 6) == 0) {
            static char new_file_name[1024];
            static char *file;
            static char new_lineno;
            token = config_input_line + 6;
            new_lineno = strtol(token, &file, 0) - 1;

            if (file == token)
                continue;	/* Not a valid #line directive, may be a comment */

            while (*file && xisspace((unsigned char) *file))
                file++;

            if (*file) {
                if (*file != '"')
                    continue;	/* Not a valid #line directive, may be a comment */

                xstrncpy(new_file_name, file + 1, sizeof(new_file_name));

                if ((token = strchr(new_file_name, '"')))
                    *token = '\0';

                cfg_filename = new_file_name;
            }

            config_lineno = new_lineno;
        }

        if (config_input_line[0] == '#')
            continue;

        if (config_input_line[0] == '\0')
            continue;

        const char* append = tmp_line_len ? skip_ws(config_input_line) : config_input_line;

        size_t append_len = strlen(append);

        tmp_line = (char*)xrealloc(tmp_line, tmp_line_len + append_len + 1);

        strcpy(tmp_line + tmp_line_len, append);

        tmp_line_len += append_len;

        if (tmp_line[tmp_line_len-1] == '\\') {
            debugs(3, 5, "parseConfigFile: tmp_line='" << tmp_line << "'");
            tmp_line[--tmp_line_len] = '\0';
            continue;
        }

        debugs(3, 5, "Processing: '" << tmp_line << "'");

	/* Handle includes here */
        if (tmp_line_len >= 9 && strncmp(tmp_line, "include", 7) == 0 && xisspace(tmp_line[7])) {
            err_count += parseManyConfigFiles(tmp_line + 8, depth + 1);
	} else if (!parse_line(tmp_line)) {
            debugs(3, 0, HERE << cfg_filename << ":" << config_lineno << " unrecognized: '" << tmp_line << "'");
 	    err_count++;
 	}

        safe_free(tmp_line);
        tmp_line_len = 0;

    }

    if (is_pipe) {
        int ret = pclose(fp);

        if (ret != 0)
            fatalf("parseConfigFile: '%s' failed with exit code %d\n", file_name, ret);
    } else {
        fclose(fp);
    }

    cfg_filename = orig_cfg_filename;
    config_lineno = orig_config_lineno;

    return err_count;
}

int
parseConfigFile(const char *file_name, CacheManager & manager)
{
    int err_count = 0;

    configFreeMemory();

    default_all();

    err_count = parseOneConfigFile(file_name, 0);

    defaults_if_none();

    /*
     * We must call configDoConfigure() before leave_suid() because
     * configDoConfigure() is where we turn username strings into
     * uid values.
     */
    configDoConfigure();

    if (!Config.chroot_dir) {
        leave_suid();
        setUmask(Config.umask);
        _db_init(Config.Log.log, Config.debugOptions);
        enter_suid();
    }

    if (opt_send_signal == -1) {
        manager.registerAction("config",
                               "Current Squid Configuration",
                               dump_config,
                               1, 1);
    }

    return err_count;
}


static void
configDoConfigure(void)
{
    memset(&Config2, '\0', sizeof(SquidConfig2));
    /* init memory as early as possible */
    memConfigure();
    /* Sanity checks */

    if (Config.cacheSwap.swapDirs == NULL)
        fatal("No cache_dir's specified in config file");

#if SIZEOF_OFF_T <= 4
    if (Config.Store.maxObjectSize > 0x7FFF0000) {
	debugs(3, 0, "WARNING: This Squid binary can not handle files larger than 2GB. Limiting maximum_object_size to just below 2GB");
	Config.Store.maxObjectSize = 0x7FFF0000;
    }
#endif
    if (0 == Store::Root().maxSize())
        /* people might want a zero-sized cache on purpose */
        (void) 0;
    else if (Store::Root().maxSize() < (Config.memMaxSize >> 10))
        /* This is bogus. folk with NULL caches will want this */
        debugs(3, 0, "WARNING cache_mem is larger than total disk cache space!");

    if (Config.Announce.period > 0) {
        Config.onoff.announce = 1;
    } else if (Config.Announce.period < 1) {
        Config.Announce.period = 86400 * 365;	/* one year */
        Config.onoff.announce = 0;
    }

    if (Config.onoff.httpd_suppress_version_string)
        visible_appname_string = (char *)appname_string;
    else
        visible_appname_string = (char *)full_appname_string;

#if USE_DNSSERVERS

    if (Config.dnsChildren < 1)
        fatal("No dnsservers allocated");

#endif

    if (Config.Program.redirect) {
        if (Config.redirectChildren < 1) {
            Config.redirectChildren = 0;
            wordlistDestroy(&Config.Program.redirect);
        }
    }

    if (Config.appendDomain)
        if (*Config.appendDomain != '.')
            fatal("append_domain must begin with a '.'");

    if (Config.errHtmlText == NULL)
        Config.errHtmlText = xstrdup(null_string);

    storeConfigure();

    snprintf(ThisCache, sizeof(ThisCache), "%s (%s)",
             uniqueHostname(),
             visible_appname_string);

    /*
     * the extra space is for loop detection in client_side.c -- we search
     * for substrings in the Via header.
     */
    snprintf(ThisCache2, sizeof(ThisCache), " %s (%s)",
             uniqueHostname(),
             visible_appname_string);

    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
        Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;

    if (Config.appendDomain)
        Config.appendDomainLen = strlen(Config.appendDomain);
    else
        Config.appendDomainLen = 0;

    safe_free(debug_options)
    debug_options = xstrdup(Config.debugOptions);

    if (Config.retry.maxtries > 10)
        fatal("maximum_single_addr_tries cannot be larger than 10");

    if (Config.retry.maxtries < 1) {
        debugs(3, 0, "WARNING: resetting 'maximum_single_addr_tries to 1");
        Config.retry.maxtries = 1;
    }

    requirePathnameExists("MIME Config Table", Config.mimeTablePathname);
#if USE_DNSSERVERS

    requirePathnameExists("cache_dns_program", Config.Program.dnsserver);
#endif
#if USE_UNLINKD

    requirePathnameExists("unlinkd_program", Config.Program.unlinkd);
#endif

    if (Config.Program.redirect)
        requirePathnameExists("redirect_program", Config.Program.redirect->key);

    requirePathnameExists("Icon Directory", Config.icons.directory);

    requirePathnameExists("Error Directory", Config.errorDirectory);

#if HTTP_VIOLATIONS

    {
        const refresh_t *R;

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.override_expire)
                continue;

            debugs(22, 1, "WARNING: use of 'override-expire' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.override_lastmod)
                continue;

            debugs(22, 1, "WARNING: use of 'override-lastmod' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.reload_into_ims)
                continue;

            debugs(22, 1, "WARNING: use of 'reload-into-ims' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.ignore_reload)
                continue;

            debugs(22, 1, "WARNING: use of 'ignore-reload' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.ignore_no_cache)
                continue;

            debugs(22, 1, "WARNING: use of 'ignore-no-cache' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.ignore_no_store)
                continue;

            debugs(22, 1, "WARNING: use of 'ignore-no-store' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.ignore_private)
                continue;

            debugs(22, 1, "WARNING: use of 'ignore-private' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.ignore_auth)
                continue;

            debugs(22, 1, "WARNING: use of 'ignore-auth' in 'refresh_pattern' violates HTTP");

            break;
        }

    }
#endif
#if !HTTP_VIOLATIONS
    Config.onoff.via = 1;
#else

    if (!Config.onoff.via)
        debugs(22, 1, "WARNING: HTTP requires the use of Via");

#endif

    if (aclPurgeMethodInUse(Config.accessList.http))
        Config2.onoff.enable_purge = 1;

    Config2.onoff.mangle_request_headers = httpReqHdrManglersConfigured();

    if (geteuid() == 0) {
        if (NULL != Config.effectiveUser) {

            struct passwd *pwd = getpwnam(Config.effectiveUser);

            if (NULL == pwd) {
                /*
                 * Andres Kroonmaa <andre@online.ee>:
                 * Some getpwnam() implementations (Solaris?) require
                 * an available FD < 256 for opening a FILE* to the
                 * passwd file.
                 * DW:
                 * This should be safe at startup, but might still fail
                 * during reconfigure.
                 */
                fatalf("getpwnam failed to find userid for effective user '%s'",
                       Config.effectiveUser);
                return;
            }

            Config2.effectiveUserID = pwd->pw_uid;

            Config2.effectiveGroupID = pwd->pw_gid;

#if HAVE_PUTENV

            if (pwd->pw_dir && *pwd->pw_dir) {
                int len;
                char *env_str = (char *)xcalloc((len = strlen(pwd->pw_dir) + 6), 1);
                snprintf(env_str, len, "HOME=%s", pwd->pw_dir);
                putenv(env_str);
            }

#endif

        }
    } else {
        Config2.effectiveUserID = geteuid();
        Config2.effectiveGroupID = getegid();
    }

    if (NULL != Config.effectiveGroup) {

        struct group *grp = getgrnam(Config.effectiveGroup);

        if (NULL == grp) {
            fatalf("getgrnam failed to find groupid for effective group '%s'",
                   Config.effectiveGroup);
            return;
        }

        Config2.effectiveGroupID = grp->gr_gid;
    }

    HttpRequestMethod::Configure(Config);
#if USE_SSL

    debugs(3, 1, "Initializing https proxy context");

    Config.ssl_client.sslContext = sslCreateClientContext(Config.ssl_client.cert, Config.ssl_client.key, Config.ssl_client.version, Config.ssl_client.cipher, Config.ssl_client.options, Config.ssl_client.flags, Config.ssl_client.cafile, Config.ssl_client.capath, Config.ssl_client.crlfile);

    {

        peer *p;

        for (p = Config.peers; p != NULL; p = p->next) {
            if (p->use_ssl) {
                debugs(3, 1, "Initializing cache_peer " << p->name << " SSL context");
                p->sslContext = sslCreateClientContext(p->sslcert, p->sslkey, p->sslversion, p->sslcipher, p->ssloptions, p->sslflags, p->sslcafile, p->sslcapath, p->sslcrlfile);
            }
        }
    }

    {

        https_port_list *s;

        for (s = Config.Sockaddr.https; s != NULL; s = (https_port_list *) s->http.next) {
            debugs(3, 1, "Initializing https_port " <<
                   inet_ntoa(s->http.s.sin_addr) << ":" <<
                   ntohs(s->http.s.sin_port) << " SSL context");

            s->sslContext = sslCreateServerContext(s->cert, s->key, s->version, s->cipher, s->options, s->sslflags, s->clientca, s->cafile, s->capath, s->crlfile, s->dhfile, s->sslcontext);
        }
    }

#endif
}

/* Parse a time specification from the config file.  Store the
 * result in 'tptr', after converting it to 'units' */
static void
parseTimeLine(time_t * tptr, const char *units)
{
    char *token;
    double d;
    time_t m;
    time_t u;

    if ((u = parseTimeUnits(units)) == 0)
        self_destruct();

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debugs(3, 0, "WARNING: No units on '" << 
                     config_input_line << "', assuming " << 
                     d << " " << units  );
    else if ((m = parseTimeUnits(token)) == 0)
        self_destruct();

    *tptr = static_cast<time_t> (m * d / u);
}

static int
parseTimeUnits(const char *unit)
{
    if (!strncasecmp(unit, T_SECOND_STR, strlen(T_SECOND_STR)))
        return 1;

    if (!strncasecmp(unit, T_MINUTE_STR, strlen(T_MINUTE_STR)))
        return 60;

    if (!strncasecmp(unit, T_HOUR_STR, strlen(T_HOUR_STR)))
        return 3600;

    if (!strncasecmp(unit, T_DAY_STR, strlen(T_DAY_STR)))
        return 86400;

    if (!strncasecmp(unit, T_WEEK_STR, strlen(T_WEEK_STR)))
        return 86400 * 7;

    if (!strncasecmp(unit, T_FORTNIGHT_STR, strlen(T_FORTNIGHT_STR)))
        return 86400 * 14;

    if (!strncasecmp(unit, T_MONTH_STR, strlen(T_MONTH_STR)))
        return 86400 * 30;

    if (!strncasecmp(unit, T_YEAR_STR, strlen(T_YEAR_STR)))
        return static_cast<int>(86400 * 365.2522);

    if (!strncasecmp(unit, T_DECADE_STR, strlen(T_DECADE_STR)))
        return static_cast<int>(86400 * 365.2522 * 10);

    debugs(3, 1, "parseTimeUnits: unknown time unit '" << unit << "'");

    return 0;
}

static void
parseBytesLine64(int64_t * bptr, const char *units)
{
    char *token;
    double d;
    int64_t m;
    int64_t u;

    if ((u = parseBytesUnits(units)) == 0) {
        self_destruct();
        return;
    }

    if ((token = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(token, "none") == 0 || strcmp(token, "-1") == 0) {
        *bptr = -1;
        return;
    }

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debugs(3, 0, "WARNING: No units on '" << 
                     config_input_line << "', assuming " <<
                     d << " " <<  units  );
    else if ((m = parseBytesUnits(token)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<int64_t>(m * d / u);

    if (static_cast<double>(*bptr) * 2 != m * d / u * 2)
        self_destruct();
}


static void
parseBytesLine(size_t * bptr, const char *units)
{
    char *token;
    double d;
    int m;
    int u;

    if ((u = parseBytesUnits(units)) == 0) {
        self_destruct();
        return;
    }

    if ((token = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(token, "none") == 0 || strcmp(token, "-1") == 0) {
        *bptr = static_cast<size_t>(-1);
        return;
    }

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debugs(3, 0, "WARNING: No units on '" << 
                     config_input_line << "', assuming " <<
                     d << " " <<  units  );
    else if ((m = parseBytesUnits(token)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<size_t>(m * d / u);

    if (static_cast<double>(*bptr) * 2 != m * d / u * 2)
        self_destruct();
}

static size_t
parseBytesUnits(const char *unit)
{
    if (!strncasecmp(unit, B_BYTES_STR, strlen(B_BYTES_STR)))
        return 1;

    if (!strncasecmp(unit, B_KBYTES_STR, strlen(B_KBYTES_STR)))
        return 1 << 10;

    if (!strncasecmp(unit, B_MBYTES_STR, strlen(B_MBYTES_STR)))
        return 1 << 20;

    if (!strncasecmp(unit, B_GBYTES_STR, strlen(B_GBYTES_STR)))
        return 1 << 30;

    debugs(3, 1, "parseBytesUnits: unknown bytes unit '" << unit << "'");

    return 0;
}

/*****************************************************************************
 * Max
 *****************************************************************************/

static void
dump_acl(StoreEntry * entry, const char *name, ACL * ae)
{
    wordlist *w;
    wordlist *v;

    while (ae != NULL) {
        debugs(3, 3, "dump_acl: " << name << " " << ae->name);
        storeAppendPrintf(entry, "%s %s %s ",
                          name,
                          ae->name,
                          ae->typeString());
        v = w = ae->dump();

        while (v != NULL) {
            debugs(3, 3, "dump_acl: " << name << " " << ae->name << " " << v->key);
            storeAppendPrintf(entry, "%s ", v->key);
            v = v->next;
        }

        storeAppendPrintf(entry, "\n");
        wordlistDestroy(&w);
        ae = ae->next;
    }
}

static void
parse_acl(ACL ** ae)
{
    ACL::ParseAclLine(LegacyParser, ae);
}

static void
free_acl(ACL ** ae)
{
    aclDestroyAcls(ae);
}

static void
dump_acl_list(StoreEntry * entry, ACLList * head)
{
    ACLList *l;

    for (l = head; l; l = l->next) {
        storeAppendPrintf(entry, " %s%s",
                          l->op ? null_string : "!",
                          l->_acl->name);
    }
}

void
dump_acl_access(StoreEntry * entry, const char *name, acl_access * head)
{
    acl_access *l;

    for (l = head; l; l = l->next) {
        storeAppendPrintf(entry, "%s %s",
                          name,
                          l->allow ? "Allow" : "Deny");
        dump_acl_list(entry, l->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void
parse_acl_access(acl_access ** head)
{
    aclParseAccessLine(LegacyParser, head);
}

static void
free_acl_access(acl_access ** head)
{
    aclDestroyAccessList(head);
}

static void

dump_address(StoreEntry * entry, const char *name, struct IN_ADDR addr)
{
    storeAppendPrintf(entry, "%s %s\n", name, inet_ntoa(addr));
}

static void

parse_address(struct IN_ADDR *addr)
{

    const struct hostent *hp;
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    if (safe_inet_addr(token, addr) == 1)
        (void) 0;
    else if ((hp = gethostbyname(token)))	/* dont use ipcache */
        *addr = inaddrFromHostent(hp);
    else
        self_destruct();
}

static void

free_address(struct IN_ADDR *addr)
{

    memset(addr, '\0', sizeof(struct IN_ADDR));
}

CBDATA_TYPE(acl_address);

static void
dump_acl_address(StoreEntry * entry, const char *name, acl_address * head)
{
    acl_address *l;

    for (l = head; l; l = l->next) {
        if (l->addr.s_addr != INADDR_ANY)
            storeAppendPrintf(entry, "%s %s", name, inet_ntoa(l->addr));
        else
            storeAppendPrintf(entry, "%s autoselect", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
freed_acl_address(void *data)
{
    acl_address *l = static_cast<acl_address *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_address(acl_address ** head)
{
    acl_address *l;
    acl_address **tail = head;	/* sane name below */
    CBDATA_INIT_TYPE_FREECB(acl_address, freed_acl_address);
    l = cbdataAlloc(acl_address);
    parse_address(&l->addr);
    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_address(acl_address ** head)
{
    while (*head) {
        acl_address *l = *head;
        *head = l->next;
        cbdataFree(l);
    }
}

CBDATA_TYPE(acl_tos);

static void
dump_acl_tos(StoreEntry * entry, const char *name, acl_tos * head)
{
    acl_tos *l;

    for (l = head; l; l = l->next) {
        if (l->tos > 0)
            storeAppendPrintf(entry, "%s 0x%02X", name, l->tos);
        else
            storeAppendPrintf(entry, "%s none", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
freed_acl_tos(void *data)
{
    acl_tos *l = static_cast<acl_tos *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_tos(acl_tos ** head)
{
    acl_tos *l;
    acl_tos **tail = head;	/* sane name below */
    int tos;
    char junk;
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    if (sscanf(token, "0x%x%c", &tos, &junk) != 1) {
        self_destruct();
        return;
    }

    if (tos < 0 || tos > 255) {
        self_destruct();
        return;
    }

    CBDATA_INIT_TYPE_FREECB(acl_tos, freed_acl_tos);

    l = cbdataAlloc(acl_tos);

    l->tos = tos;

    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_tos(acl_tos ** head)
{
    while (*head) {
        acl_tos *l = *head;
        *head = l->next;
        l->next = NULL;
        cbdataFree(l);
    }
}

CBDATA_TYPE(acl_size_t);

static void
dump_acl_b_size_t(StoreEntry * entry, const char *name, acl_size_t * head)
{
    acl_size_t *l;

    for (l = head; l; l = l->next) {
        if (l->size != -1)
            storeAppendPrintf(entry, "%s %d %s\n", name, (int) l->size, B_BYTES_STR);
        else
            storeAppendPrintf(entry, "%s none", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
freed_acl_b_size_t(void *data)
{
    acl_size_t *l = static_cast<acl_size_t *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_b_size_t(acl_size_t ** head)
{
    acl_size_t *l;
    acl_size_t **tail = head;	/* sane name below */

    CBDATA_INIT_TYPE_FREECB(acl_size_t, freed_acl_b_size_t);

    l = cbdataAlloc(acl_size_t);

    parse_b_int64_t(&l->size);

    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_b_size_t(acl_size_t ** head)
{
    while (*head) {
        acl_size_t *l = *head;
        *head = l->next;
        l->next = NULL;
        cbdataFree(l);
    }
}

#if DELAY_POOLS

#include "DelayPools.h"
#include "DelayConfig.h"
/* do nothing - free_delay_pool_count is the magic free function.
 * this is why delay_pool_count isn't just marked TYPE: ushort
 */
#define free_delay_pool_class(X)
#define free_delay_pool_access(X)
#define free_delay_pool_rates(X)
#define dump_delay_pool_class(X, Y, Z)
#define dump_delay_pool_access(X, Y, Z)
#define dump_delay_pool_rates(X, Y, Z)

static void
free_delay_pool_count(DelayConfig * cfg)
{
    cfg->freePoolCount();
}

static void
dump_delay_pool_count(StoreEntry * entry, const char *name, DelayConfig &cfg)
{
    cfg.dumpPoolCount (entry, name);
}

static void
parse_delay_pool_count(DelayConfig * cfg)
{
    cfg->parsePoolCount();
}

static void
parse_delay_pool_class(DelayConfig * cfg)
{
    cfg->parsePoolClass();
}

static void
parse_delay_pool_rates(DelayConfig * cfg)
{
    cfg->parsePoolRates();
}

static void
parse_delay_pool_access(DelayConfig * cfg)
{
    cfg->parsePoolAccess(LegacyParser);
}

#endif

#if HTTP_VIOLATIONS
static void
dump_http_header_access(StoreEntry * entry, const char *name, header_mangler header[])
{
    int i;

    for (i = 0; i < HDR_ENUM_END; i++) {
        if (header[i].access_list != NULL) {
            storeAppendPrintf(entry, "%s ", name);
            dump_acl_access(entry, httpHeaderNameById(i),
                            header[i].access_list);
        }
    }
}

static void
parse_http_header_access(header_mangler header[])
{
    int id, i;
    char *t = NULL;

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(3, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, 0, "parse_http_header_access: missing header name.");
        return;
    }

    /* Now lookup index of header. */
    id = httpHeaderIdByNameDef(t, strlen(t));

    if (strcmp(t, "All") == 0)
        id = HDR_ENUM_END;
    else if (strcmp(t, "Other") == 0)
        id = HDR_OTHER;
    else if (id == -1) {
        debugs(3, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, 0, "parse_http_header_access: unknown header name '" << t << "'");
        return;
    }

    if (id != HDR_ENUM_END) {
        parse_acl_access(&header[id].access_list);
    } else {
        char *next_string = t + strlen(t) - 1;
        *next_string = 'A';
        *(next_string + 1) = ' ';

        for (i = 0; i < HDR_ENUM_END; i++) {
            char *new_string = xstrdup(next_string);
            strtok(new_string, w_space);
            parse_acl_access(&header[i].access_list);
            safe_free(new_string);
        }
    }
}

static void
free_http_header_access(header_mangler header[])
{
    int i;

    for (i = 0; i < HDR_ENUM_END; i++) {
        free_acl_access(&header[i].access_list);
    }
}

static void
dump_http_header_replace(StoreEntry * entry, const char *name, header_mangler
                         header[])
{
    int i;

    for (i = 0; i < HDR_ENUM_END; i++) {
        if (NULL == header[i].replacement)
            continue;

        storeAppendPrintf(entry, "%s %s %s\n", name, httpHeaderNameById(i),
                          header[i].replacement);
    }
}

static void
parse_http_header_replace(header_mangler header[])
{
    int id, i;
    char *t = NULL;

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(3, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, 0, "parse_http_header_replace: missing header name.");
        return;
    }

    /* Now lookup index of header. */
    id = httpHeaderIdByNameDef(t, strlen(t));

    if (strcmp(t, "All") == 0)
        id = HDR_ENUM_END;
    else if (strcmp(t, "Other") == 0)
        id = HDR_OTHER;
    else if (id == -1) {
        debugs(3, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, 0, "parse_http_header_replace: unknown header name " << t << ".");

        return;
    }

    if (id != HDR_ENUM_END) {
        if (header[id].replacement != NULL)
            safe_free(header[id].replacement);

        header[id].replacement = xstrdup(t + strlen(t) + 1);
    } else {
        for (i = 0; i < HDR_ENUM_END; i++) {
            if (header[i].replacement != NULL)
                safe_free(header[i].replacement);

            header[i].replacement = xstrdup(t + strlen(t) + 1);
        }
    }
}

static void
free_http_header_replace(header_mangler header[])
{
    int i;

    for (i = 0; i < HDR_ENUM_END; i++) {
        if (header[i].replacement != NULL)
            safe_free(header[i].replacement);
    }
}

#endif

static void
dump_cachedir(StoreEntry * entry, const char *name, _SquidConfig::_cacheSwap swap)
{
    SwapDir *s;
    int i;
    assert (entry);

    for (i = 0; i < swap.n_configured; i++) {
        s = dynamic_cast<SwapDir *>(swap.swapDirs[i].getRaw());
        if(!s) continue;
        storeAppendPrintf(entry, "%s %s %s", name, s->type(), s->path);
        s->dump(*entry);
        storeAppendPrintf(entry, "\n");
    }
}

static int
check_null_cachedir(_SquidConfig::_cacheSwap swap)
{
    return swap.swapDirs == NULL;
}

static int
check_null_string(char *s)
{
    return s == NULL;
}

static void
parse_authparam(authConfig * config)
{
    char *type_str;
    char *param_str;

    if ((type_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((param_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    /* find a configuration for the scheme */
    AuthConfig *scheme = AuthConfig::Find (type_str);

    if (scheme == NULL) {
        /* Create a configuration */
        AuthScheme *theScheme;

        if ((theScheme = AuthScheme::Find(type_str)) == NULL) {
            debugs(3, 0, "Parsing Config File: Unknown authentication scheme '" << type_str << "'.");
            return;
        }

        config->push_back(theScheme->createConfig());
        scheme = config->back();
        assert (scheme);
    }

    scheme->parse(scheme, config->size(), param_str);
}

static void
free_authparam(authConfig * cfg)
{
    AuthConfig *scheme;
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    while (cfg->size()) {
        scheme = cfg->pop_back();
        scheme->done();
    }
}

static void
dump_authparam(StoreEntry * entry, const char *name, authConfig cfg)
{
    for (authConfig::iterator  i = cfg.begin(); i != cfg.end(); ++i)
        (*i)->dump(entry, name, (*i));
}

/* TODO: just return the object, the # is irrelevant */
static int
find_fstype(char *type)
{
    for (size_t i = 0; i < StoreFileSystem::FileSystems().size(); ++i)
        if (strcasecmp(type, StoreFileSystem::FileSystems().items[i]->type()) == 0)
            return (int)i;

    return (-1);
}

static void
parse_cachedir(_SquidConfig::_cacheSwap * swap)
{
    char *type_str;
    char *path_str;
    RefCount<SwapDir> sd;
    int i;
    int fs;

    if ((type_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((path_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    fs = find_fstype(type_str);

    if (fs < 0)
        self_destruct();

    /* reconfigure existing dir */

    for (i = 0; i < swap->n_configured; i++) {
        assert (swap->swapDirs[i].getRaw());

        if ((strcasecmp(path_str, dynamic_cast<SwapDir *>(swap->swapDirs[i].getRaw())->path)
            ) == 0) {
            /* this is specific to on-fs Stores. The right
             * way to handle this is probably to have a mapping 
             * from paths to stores, and have on-fs stores
             * register with that, and lookip in that in their
             * own setup logic. RBC 20041225. TODO.
             */

            sd = dynamic_cast<SwapDir *>(swap->swapDirs[i].getRaw());

            if (sd->type() != StoreFileSystem::FileSystems().items[fs]->type()) {
                debugs(3, 0, "ERROR: Can't change type of existing cache_dir " <<
                       sd->type() << " " << sd->path << " to " << type_str << ". Restart required");
                return;
            }

            sd->reconfigure (i, path_str);

            update_maxobjsize();

            return;
        }
    }

    /* new cache_dir */
    assert(swap->n_configured < 63);	/* 7 bits, signed */

    allocate_new_swapdir(swap);

    swap->swapDirs[swap->n_configured] = StoreFileSystem::FileSystems().items[fs]->createSwapDir();

    sd = dynamic_cast<SwapDir *>(swap->swapDirs[swap->n_configured].getRaw());

    /* parse the FS parameters and options */
    sd->parse(swap->n_configured, path_str);

    ++swap->n_configured;

    /* Update the max object size */
    update_maxobjsize();
}

static const char *
peer_type_str(const peer_t type)
{
    const char * result;

    switch (type) {

    case PEER_PARENT:
        result = "parent";
        break;

    case PEER_SIBLING:
        result = "sibling";
        break;

    case PEER_MULTICAST:
        result = "multicast";
        break;

    default:
        result = "unknown";
        break;
    }

    return result;
}

static void
dump_peer(StoreEntry * entry, const char *name, peer * p)
{
    domain_ping *d;
    domain_type *t;
    LOCAL_ARRAY(char, xname, 128);

    while (p != NULL) {
        storeAppendPrintf(entry, "%s %s %s %d %d",
                          name,
                          p->host,
                          neighborTypeStr(p),
                          p->http_port,
                          p->icp.port);
        dump_peer_options(entry, p);

        for (d = p->peer_domain; d; d = d->next) {
            storeAppendPrintf(entry, "cache_peer_domain %s %s%s\n",
                              p->host,
                              d->do_ping ? null_string : "!",
                              d->domain);
        }

        if (p->access) {
            snprintf(xname, 128, "cache_peer_access %s", p->name);
            dump_acl_access(entry, xname, p->access);
        }

        for (t = p->typelist; t; t = t->next) {
            storeAppendPrintf(entry, "neighbor_type_domain %s %s %s\n",
                              p->host,
                              peer_type_str(t->type),
                              t->domain);
        }

        p = p->next;
    }
}

/**
 \param proto	'tcp' or 'udp' for protocol
 \returns       Port the named service is supposed to be listening on.
 */
static u_short
GetService(const char *proto)
{
    struct servent *port = NULL;
    /** Parses a port number or service name from the squid.conf */
    char *token = strtok(NULL, w_space);
    if (token == NULL) {
       self_destruct();
       return 0; /* NEVER REACHED */
    }
    /** Returns either the service port number from /etc/services */
    port = getservbyname(token, proto);
    if (port != NULL) {
        return ntohs((u_short)port->s_port);
    }
    /** Or a numeric translation of the config text. */
    return xatos(token);
}

/**
 \returns       Port the named TCP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline u_short
GetTcpService(void)
{
    return GetService("tcp");
}

/**
 \returns       Port the named UDP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline u_short
GetUdpService(void)
{
    return GetService("udp");
}

static void
parse_peer(peer ** head)
{
    char *token = NULL;
    peer *p;
    CBDATA_INIT_TYPE_FREECB(peer, peerDestroy);
    p = cbdataAlloc(peer);
    p->http_port = CACHE_HTTP_PORT;
    p->icp.port = CACHE_ICP_PORT;
    p->weight = 1;
    p->basetime = 0;
    p->stats.logged_state = PEER_ALIVE;

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    p->host = xstrdup(token);

    p->name = xstrdup(token);

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    p->type = parseNeighborType(token);

    if (p->type == PEER_MULTICAST) {
        p->options.no_digest = 1;
        p->options.no_netdb_exchange = 1;
    }

    p->http_port = GetTcpService();

    if (!p->http_port)
        self_destruct();

    p->icp.port = GetUdpService();

    while ((token = strtok(NULL, w_space))) {
        if (!strcasecmp(token, "proxy-only")) {
            p->options.proxy_only = 1;
        } else if (!strcasecmp(token, "no-query")) {
            p->options.no_query = 1;
        } else if (!strcasecmp(token, "background-ping")) {
            p->options.background_ping = 1;
        } else if (!strcasecmp(token, "no-digest")) {
            p->options.no_digest = 1;
        } else if (!strcasecmp(token, "multicast-responder")) {
            p->options.mcast_responder = 1;
        } else if (!strncasecmp(token, "weight=", 7)) {
            p->weight = xatoi(token + 7);
        } else if (!strncasecmp(token, "basetime=", 9)) {
            p->basetime = xatoi(token + 9);
        } else if (!strcasecmp(token, "closest-only")) {
            p->options.closest_only = 1;
        } else if (!strncasecmp(token, "ttl=", 4)) {
            p->mcast.ttl = xatoi(token + 4);

            if (p->mcast.ttl < 0)
                p->mcast.ttl = 0;

            if (p->mcast.ttl > 128)
                p->mcast.ttl = 128;
        } else if (!strcasecmp(token, "default")) {
            p->options.default_parent = 1;
        } else if (!strcasecmp(token, "round-robin")) {
            p->options.roundrobin = 1;
        } else if (!strcasecmp(token, "weighted-round-robin")) {
            p->options.weighted_roundrobin = 1;
#if USE_HTCP

        } else if (!strcasecmp(token, "htcp")) {
            p->options.htcp = 1;
        } else if (!strcasecmp(token, "htcp-oldsquid")) {
            p->options.htcp = 1;
            p->options.htcp_oldsquid = 1;
#endif

        } else if (!strcasecmp(token, "no-netdb-exchange")) {
            p->options.no_netdb_exchange = 1;
#if USE_CARP

        } else if (!strcasecmp(token, "carp")) {
            if (p->type != PEER_PARENT)
                fatalf("parse_peer: non-parent carp peer %s/%d\n", p->host, p->http_port);

            p->options.carp = 1;

#endif
#if DELAY_POOLS

        } else if (!strcasecmp(token, "no-delay")) {
            p->options.no_delay = 1;
#endif

        } else if (!strncasecmp(token, "login=", 6)) {
            p->login = xstrdup(token + 6);
            rfc1738_unescape(p->login);
        } else if (!strncasecmp(token, "connect-timeout=", 16)) {
            p->connect_timeout = xatoi(token + 16);
#if USE_CACHE_DIGESTS

        } else if (!strncasecmp(token, "digest-url=", 11)) {
            p->digest_url = xstrdup(token + 11);
#endif

        } else if (!strcasecmp(token, "allow-miss")) {
            p->options.allow_miss = 1;
        } else if (!strncasecmp(token, "max-conn=", 9)) {
            p->max_conn = xatoi(token + 9);
        } else if (!strcasecmp(token, "originserver")) {
            p->options.originserver = 1;
        } else if (!strncasecmp(token, "name=", 5)) {
            safe_free(p->name);

            if (token[5])
                p->name = xstrdup(token + 5);
        } else if (!strncasecmp(token, "forceddomain=", 13)) {
            safe_free(p->domain);

            if (token[13])
                p->domain = xstrdup(token + 13);

#if USE_SSL

        } else if (strcmp(token, "ssl") == 0) {
            p->use_ssl = 1;
        } else if (strncmp(token, "sslcert=", 8) == 0) {
            safe_free(p->sslcert);
            p->sslcert = xstrdup(token + 8);
        } else if (strncmp(token, "sslkey=", 7) == 0) {
            safe_free(p->sslkey);
            p->sslkey = xstrdup(token + 7);
        } else if (strncmp(token, "sslversion=", 11) == 0) {
            p->sslversion = atoi(token + 11);
        } else if (strncmp(token, "ssloptions=", 11) == 0) {
            safe_free(p->ssloptions);
            p->ssloptions = xstrdup(token + 11);
        } else if (strncmp(token, "sslcipher=", 10) == 0) {
            safe_free(p->sslcipher);
            p->sslcipher = xstrdup(token + 10);
        } else if (strncmp(token, "sslcafile=", 10) == 0) {
            safe_free(p->sslcafile);
            p->sslcafile = xstrdup(token + 10);
        } else if (strncmp(token, "sslcapath=", 10) == 0) {
            safe_free(p->sslcapath);
            p->sslcapath = xstrdup(token + 10);
        } else if (strncmp(token, "sslcrlfile=", 11) == 0) {
            safe_free(p->sslcrlfile);
            p->sslcapath = xstrdup(token + 10);
        } else if (strncmp(token, "sslflags=", 9) == 0) {
            safe_free(p->sslflags);
            p->sslflags = xstrdup(token + 9);
        } else if (strncmp(token, "ssldomain=", 10) == 0) {
            safe_free(p->ssldomain);
            p->ssldomain = xstrdup(token + 10);
#endif

        } else if (strcmp(token, "front-end-https") == 0) {
            p->front_end_https = 1;
        } else if (strcmp(token, "front-end-https=on") == 0) {
            p->front_end_https = 1;
        } else if (strcmp(token, "front-end-https=auto") == 0) {
            p->front_end_https = 2;
        } else {
            debugs(3, 0, "parse_peer: token='" << token << "'");
            self_destruct();
        }
    }

    if (peerFindByName(p->name))
        fatalf("ERROR: cache_peer %s specified twice\n", p->name);

    if (p->weight < 1)
        p->weight = 1;

    p->icp.version = ICP_VERSION_CURRENT;

    p->test_fd = -1;

#if USE_CACHE_DIGESTS

    if (!p->options.no_digest) {
        /* XXX This looks odd.. who has the original pointer
         * then?
         */
        PeerDigest *pd = peerDigestCreate(p);
        p->digest = cbdataReference(pd);
    }

#endif
    while (*head != NULL)
        head = &(*head)->next;

    *head = p;

    Config.npeers++;

    peerClearRR(p);
}

static void
free_peer(peer ** P)
{
    peer *p;

    while ((p = *P) != NULL) {
        *P = p->next;
#if USE_CACHE_DIGESTS

        cbdataReferenceDone(p->digest);
#endif

        cbdataFree(p);
    }

    Config.npeers = 0;
}

static void
dump_cachemgrpasswd(StoreEntry * entry, const char *name, cachemgr_passwd * list)
{
    wordlist *w;

    while (list != NULL) {
        if (strcmp(list->passwd, "none") && strcmp(list->passwd, "disable"))
            storeAppendPrintf(entry, "%s XXXXXXXXXX", name);
        else
            storeAppendPrintf(entry, "%s %s", name, list->passwd);

        for (w = list->actions; w != NULL; w = w->next) {
            storeAppendPrintf(entry, " %s", w->key);
        }

        storeAppendPrintf(entry, "\n");
        list = list->next;
    }
}

static void
parse_cachemgrpasswd(cachemgr_passwd ** head)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    cachemgr_passwd *p;
    cachemgr_passwd **P;
    parse_string(&passwd);
    parse_wordlist(&actions);
    p = static_cast<cachemgr_passwd *>(xcalloc(1, sizeof(cachemgr_passwd)));
    p->passwd = passwd;
    p->actions = actions;

    for (P = head; *P; P = &(*P)->next) {
        /*
         * See if any of the actions from this line already have a
         * password from previous lines.  The password checking
         * routines in cache_manager.c take the the password from
         * the first cachemgr_passwd struct that contains the
         * requested action.  Thus, we should warn users who might
         * think they can have two passwords for the same action.
         */
        wordlist *w;
        wordlist *u;

        for (w = (*P)->actions; w; w = w->next) {
            for (u = actions; u; u = u->next) {
                if (strcmp(w->key, u->key))
                    continue;

                debugs(0, 0, "WARNING: action '" << u->key << "' (line " << config_lineno << ") already has a password");
            }
        }
    }

    *P = p;
}

static void
free_cachemgrpasswd(cachemgr_passwd ** head)
{
    cachemgr_passwd *p;

    while ((p = *head) != NULL) {
        *head = p->next;
        xfree(p->passwd);
        wordlistDestroy(&p->actions);
        xfree(p);
    }
}

static void
dump_denyinfo(StoreEntry * entry, const char *name, acl_deny_info_list * var)
{
    acl_name_list *a;

    while (var != NULL) {
        storeAppendPrintf(entry, "%s %s", name, var->err_page_name);

        for (a = var->acl_list; a != NULL; a = a->next)
            storeAppendPrintf(entry, " %s", a->name);

        storeAppendPrintf(entry, "\n");

        var = var->next;
    }
}

static void
parse_denyinfo(acl_deny_info_list ** var)
{
    aclParseDenyInfoLine(var);
}

void
free_denyinfo(acl_deny_info_list ** list)
{
    acl_deny_info_list *a = NULL;
    acl_deny_info_list *a_next = NULL;
    acl_name_list *l = NULL;
    acl_name_list *l_next = NULL;

    for (a = *list; a; a = a_next) {
        for (l = a->acl_list; l; l = l_next) {
            l_next = l->next;
            memFree(l, MEM_ACL_NAME_LIST);
            l = NULL;
        }

        a_next = a->next;
        memFree(a, MEM_ACL_DENY_INFO_LIST);
        a = NULL;
    }

    *list = NULL;
}

static void
parse_peer_access(void)
{
    char *host = NULL;
    peer *p;

    if (!(host = strtok(NULL, w_space)))
        self_destruct();

    if ((p = peerFindByName(host)) == NULL) {
        debugs(15, 0, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
        return;
    }

    aclParseAccessLine(LegacyParser, &p->access);
}

static void
parse_hostdomain(void)
{
    char *host = NULL;
    char *domain = NULL;

    if (!(host = strtok(NULL, w_space)))
        self_destruct();

    while ((domain = strtok(NULL, list_sep))) {
        domain_ping *l = NULL;
        domain_ping **L = NULL;
        peer *p;

        if ((p = peerFindByName(host)) == NULL) {
            debugs(15, 0, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
            continue;
        }

        l = static_cast<domain_ping *>(xcalloc(1, sizeof(domain_ping)));
        l->do_ping = 1;

        if (*domain == '!') {	/* check for !.edu */
            l->do_ping = 0;
            domain++;
        }

        l->domain = xstrdup(domain);

        for (L = &(p->peer_domain); *L; L = &((*L)->next))

            ;
        *L = l;
    }
}

static void
parse_hostdomaintype(void)
{
    char *host = NULL;
    char *type = NULL;
    char *domain = NULL;

    if (!(host = strtok(NULL, w_space)))
        self_destruct();

    if (!(type = strtok(NULL, w_space)))
        self_destruct();

    while ((domain = strtok(NULL, list_sep))) {
        domain_type *l = NULL;
        domain_type **L = NULL;
        peer *p;

        if ((p = peerFindByName(host)) == NULL) {
            debugs(15, 0, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
            return;
        }

        l = static_cast<domain_type *>(xcalloc(1, sizeof(domain_type)));
        l->type = parseNeighborType(type);
        l->domain = xstrdup(domain);

        for (L = &(p->typelist); *L; L = &((*L)->next))

            ;
        *L = l;
    }
}

static void
dump_int(StoreEntry * entry, const char *name, int var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

void
parse_int(int *var)
{
    int i;
    i = GetInteger();
    *var = i;
}

static void
free_int(int *var)
{
    *var = 0;
}

static void
dump_onoff(StoreEntry * entry, const char *name, int var)
{
    storeAppendPrintf(entry, "%s %s\n", name, var ? "on" : "off");
}

void
parse_onoff(int *var)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
        *var = 1;
    else
        *var = 0;
}

#define free_onoff free_int

static void
dump_tristate(StoreEntry * entry, const char *name, int var)
{
    const char *state;

    if (var > 0)
        state = "on";
    else if (var < 0)
        state = "warn";
    else
        state = "off";

    storeAppendPrintf(entry, "%s %s\n", name, state);
}

static void
parse_tristate(int *var)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
        *var = 1;
    else if (!strcasecmp(token, "warn"))
        *var = -1;
    else
        *var = 0;
}

#define free_tristate free_int

static void
dump_refreshpattern(StoreEntry * entry, const char *name, refresh_t * head)
{
    while (head != NULL) {
        storeAppendPrintf(entry, "%s%s %s %d %d%% %d\n",
                          name,
                          head->flags.icase ? " -i" : null_string,
                          head->pattern,
                          (int) head->min / 60,
                          (int) (100.0 * head->pct + 0.5),
                          (int) head->max / 60);

        if (head->flags.refresh_ims)
            storeAppendPrintf(entry, " refresh-ims");

#if HTTP_VIOLATIONS

        if (head->flags.override_expire)
            storeAppendPrintf(entry, " override-expire");

        if (head->flags.override_lastmod)
            storeAppendPrintf(entry, " override-lastmod");

        if (head->flags.reload_into_ims)
            storeAppendPrintf(entry, " reload-into-ims");

        if (head->flags.ignore_reload)
            storeAppendPrintf(entry, " ignore-reload");

        if (head->flags.ignore_no_cache)
            storeAppendPrintf(entry, " ignore-no-cache");

        if (head->flags.ignore_no_store)
            storeAppendPrintf(entry, " ignore-no-store");

        if (head->flags.ignore_private)
            storeAppendPrintf(entry, " ignore-private");

        if (head->flags.ignore_auth)
            storeAppendPrintf(entry, " ignore-auth");

#endif

        storeAppendPrintf(entry, "\n");

        head = head->next;
    }
}

static void
parse_refreshpattern(refresh_t ** head)
{
    char *token;
    char *pattern;
    time_t min = 0;
    double pct = 0.0;
    time_t max = 0;
    int refresh_ims = 0;
#if HTTP_VIOLATIONS

    int override_expire = 0;
    int override_lastmod = 0;
    int reload_into_ims = 0;
    int ignore_reload = 0;
    int ignore_no_cache = 0;
    int ignore_no_store = 0;
    int ignore_private = 0;
    int ignore_auth = 0;
#endif

    int i;
    refresh_t *t;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;

    if ((token = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(token, "-i") == 0) {
        flags |= REG_ICASE;
        token = strtok(NULL, w_space);
    } else if (strcmp(token, "+i") == 0) {
        flags &= ~REG_ICASE;
        token = strtok(NULL, w_space);
    }

    if (token == NULL) {
        self_destruct();
        return;
    }

    pattern = xstrdup(token);

    i = GetInteger();		/* token: min */

    min = (time_t) (i * 60);	/* convert minutes to seconds */

    i = GetInteger();		/* token: pct */

    pct = (double) i / 100.0;

    i = GetInteger();		/* token: max */

    max = (time_t) (i * 60);	/* convert minutes to seconds */

    /* Options */
    while ((token = strtok(NULL, w_space)) != NULL) {
        if (!strcmp(token, "refresh-ims")) {
            refresh_ims = 1;
#if HTTP_VIOLATIONS

        } else if (!strcmp(token, "override-expire"))
            override_expire = 1;
        else if (!strcmp(token, "override-lastmod"))
            override_lastmod = 1;
        else if (!strcmp(token, "ignore-no-cache"))
            ignore_no_cache = 1;
        else if (!strcmp(token, "ignore-no-store"))
            ignore_no_store = 1;
        else if (!strcmp(token, "ignore-private"))
            ignore_private = 1;
        else if (!strcmp(token, "ignore-auth"))
            ignore_auth = 1;
        else if (!strcmp(token, "reload-into-ims")) {
            reload_into_ims = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
        } else if (!strcmp(token, "ignore-reload")) {
            ignore_reload = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
#endif

        } else
             debugs(22, 0, "redreshAddToList: Unknown option '" << pattern << "': " << token);
    }

    if ((errcode = regcomp(&comp, pattern, flags)) != 0) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        debugs(22, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(22, 0, "refreshAddToList: Invalid regular expression '" << pattern << "': " << errbuf);
        return;
    }

    pct = pct < 0.0 ? 0.0 : pct;
    max = max < 0 ? 0 : max;
    t = static_cast<refresh_t *>(xcalloc(1, sizeof(refresh_t)));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->min = min;
    t->pct = pct;
    t->max = max;

    if (flags & REG_ICASE)
        t->flags.icase = 1;

    if (refresh_ims)
        t->flags.refresh_ims = 1;

#if HTTP_VIOLATIONS

    if (override_expire)
        t->flags.override_expire = 1;

    if (override_lastmod)
        t->flags.override_lastmod = 1;

    if (reload_into_ims)
        t->flags.reload_into_ims = 1;

    if (ignore_reload)
        t->flags.ignore_reload = 1;

    if (ignore_no_cache)
        t->flags.ignore_no_cache = 1;

    if (ignore_no_store)
        t->flags.ignore_no_store = 1;

    if (ignore_private)
        t->flags.ignore_private = 1;

    if (ignore_auth)
        t->flags.ignore_auth = 1;

#endif

    t->next = NULL;

    while (*head)
        head = &(*head)->next;

    *head = t;

    safe_free(pattern);
}

static void
free_refreshpattern(refresh_t ** head)
{
    refresh_t *t;

    while ((t = *head) != NULL) {
        *head = t->next;
        safe_free(t->pattern);
        regfree(&t->compiled_pattern);
        safe_free(t);
    }

#if HTTP_VIOLATIONS
    refresh_nocache_hack = 0;

#endif
}

static void
dump_string(StoreEntry * entry, const char *name, char *var)
{
    if (var != NULL)
        storeAppendPrintf(entry, "%s %s\n", name, var);
}

static void
parse_string(char **var)
{
    char *token = strtok(NULL, w_space);
    safe_free(*var);

    if (token == NULL)
        self_destruct();

    *var = xstrdup(token);
}

void
ConfigParser::ParseString(char **var)
{
    parse_string(var);
}

void
ConfigParser::ParseString(String *var)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    var->reset(token);
}

static void
free_string(char **var)
{
    safe_free(*var);
}

void
parse_eol(char *volatile *var)
{
    unsigned char *token = (unsigned char *) strtok(NULL, null_string);
    safe_free(*var);

    if (!token) {
        self_destruct();
        return;
    }

    while (*token && xisspace(*token))
        token++;

    if (!*token) {
        self_destruct();
        return;
    }

    *var = xstrdup((char *) token);
}

#define dump_eol dump_string
#define free_eol free_string

static void
dump_time_t(StoreEntry * entry, const char *name, time_t var)
{
    storeAppendPrintf(entry, "%s %d seconds\n", name, (int) var);
}

void
parse_time_t(time_t * var)
{
    parseTimeLine(var, T_SECOND_STR);
}

static void
free_time_t(time_t * var)
{
    *var = 0;
}

static void
dump_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d\n", name, (int) var);
}

static void
dump_b_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}

#if UNUSED_CODE
static void
dump_kb_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_KBYTES_STR);
}
#endif

static void
dump_b_int64_t(StoreEntry * entry, const char *name, int64_t var)
{
    storeAppendPrintf(entry, "%s %"PRId64" %s\n", name, var, B_BYTES_STR);
}

static void
dump_kb_int64_t(StoreEntry * entry, const char *name, int64_t var)
{
    storeAppendPrintf(entry, "%s %"PRId64" %s\n", name, var, B_KBYTES_STR);
}

static void
parse_size_t(size_t * var)
{
    int i;
    i = GetInteger();
    *var = (size_t) i;
}

static void
parse_b_size_t(size_t * var)
{
    parseBytesLine(var, B_BYTES_STR);
}

#if UNUSED_CODE
static void
parse_kb_size_t(size_t * var)
{
    parseBytesLine(var, B_KBYTES_STR);
}
#endif

static void
parse_b_int64_t(int64_t * var)
{
    parseBytesLine64(var, B_BYTES_STR);
}

static void
parse_kb_int64_t(int64_t * var)
{
    parseBytesLine64(var, B_KBYTES_STR);
}

static void
free_size_t(size_t * var)
{
    *var = 0;
}

static void
free_b_int64_t(int64_t * var)
{
    *var = 0;
}

#define free_b_size_t free_size_t
#define free_kb_size_t free_size_t
#define free_mb_size_t free_size_t
#define free_gb_size_t free_size_t
#define free_kb_int64_t free_b_int64_t

static void
dump_ushort(StoreEntry * entry, const char *name, u_short var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

static void
free_ushort(u_short * u)
{
    *u = 0;
}

static void
parse_ushort(u_short * var)
{
    ConfigParser::ParseUShort(var);
}

void
ConfigParser::ParseUShort(u_short *var)
{
    *var = GetShort();
}

void
ConfigParser::ParseBool(bool *var)
{
    int i = GetInteger();

    if (0 == i)
        *var = false;
    else if (1 == i)
        *var = true;
    else
        self_destruct();
}

static void
dump_wordlist(StoreEntry * entry, const char *name, wordlist * list)
{
    while (list != NULL) {
        storeAppendPrintf(entry, "%s %s\n", name, list->key);
        list = list->next;
    }
}

void
ConfigParser::ParseWordList(wordlist ** list)
{
    parse_wordlist(list);
}

void
parse_wordlist(wordlist ** list)
{
    char *token;
    char *t = strtok(NULL, "");

    while ((token = strwordtok(NULL, &t)))
        wordlistAdd(list, token);
}

static int
check_null_wordlist(wordlist * w)
{
    return w == NULL;
}

static int
check_null_acl_access(acl_access * a)
{
    return a == NULL;
}

#define free_wordlist wordlistDestroy

#define free_uri_whitespace free_int

static void
parse_uri_whitespace(int *var)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    if (!strcasecmp(token, "strip"))
        *var = URI_WHITESPACE_STRIP;
    else if (!strcasecmp(token, "deny"))
        *var = URI_WHITESPACE_DENY;
    else if (!strcasecmp(token, "allow"))
        *var = URI_WHITESPACE_ALLOW;
    else if (!strcasecmp(token, "encode"))
        *var = URI_WHITESPACE_ENCODE;
    else if (!strcasecmp(token, "chop"))
        *var = URI_WHITESPACE_CHOP;
    else
        self_destruct();
}

static void
dump_uri_whitespace(StoreEntry * entry, const char *name, int var)
{
    const char *s;

    if (var == URI_WHITESPACE_ALLOW)
        s = "allow";
    else if (var == URI_WHITESPACE_ENCODE)
        s = "encode";
    else if (var == URI_WHITESPACE_CHOP)
        s = "chop";
    else if (var == URI_WHITESPACE_DENY)
        s = "deny";
    else
        s = "strip";

    storeAppendPrintf(entry, "%s %s\n", name, s);
}

static void
free_removalpolicy(RemovalPolicySettings ** settings)
{
    if (!*settings)
        return;

    free_string(&(*settings)->type);

    free_wordlist(&(*settings)->args);

    delete *settings;

    *settings = NULL;
}

static void
parse_removalpolicy(RemovalPolicySettings ** settings)
{
    if (*settings)
        free_removalpolicy(settings);

    *settings = new RemovalPolicySettings;

    parse_string(&(*settings)->type);

    parse_wordlist(&(*settings)->args);
}

static void
dump_removalpolicy(StoreEntry * entry, const char *name, RemovalPolicySettings * settings)
{
    wordlist *args;
    storeAppendPrintf(entry, "%s %s", name, settings->type);
    args = settings->args;

    while (args) {
        storeAppendPrintf(entry, " %s", args->key);
        args = args->next;
    }

    storeAppendPrintf(entry, "\n");
}

#include "cf_parser.h"

peer_t
parseNeighborType(const char *s)
{
    if (!strcasecmp(s, "parent"))
        return PEER_PARENT;

    if (!strcasecmp(s, "neighbor"))
        return PEER_SIBLING;

    if (!strcasecmp(s, "neighbour"))
        return PEER_SIBLING;

    if (!strcasecmp(s, "sibling"))
        return PEER_SIBLING;

    if (!strcasecmp(s, "multicast"))
        return PEER_MULTICAST;

    debugs(15, 0, "WARNING: Unknown neighbor type: " << s);

    return PEER_SIBLING;
}

#if USE_WCCPv2
void
parse_sockaddr_in_list_token(sockaddr_in_list ** head, char *token)
{
    char *t;
    char *host;
    char *tmp;

    const struct hostent *hp;
    unsigned short port;
    sockaddr_in_list *s;

    host = NULL;
    port = 0;

    if ((t = strchr(token, ':'))) {
        /* host:port */
        host = token;
        *t = '\0';
        port = xatos(t + 1);

        if (0 == port)
            self_destruct();
    } else if ((port = strtol(token, &tmp, 10)), !*tmp) {
        /* port */
    } else {
        host = token;
        port = 0;
    }

    s = static_cast<sockaddr_in_list *>(xcalloc(1, sizeof(*s)));
    s->s.sin_port = htons(port);

    if (NULL == host)
        s->s.sin_addr = any_addr;
    else if (1 == safe_inet_addr(host, &s->s.sin_addr))
        (void) 0;
    else if ((hp = gethostbyname(host)))	/* dont use ipcache */
        s->s.sin_addr = inaddrFromHostent(hp);
    else
        self_destruct();

    while (*head)
        head = &(*head)->next;

    *head = s;
}

static void
parse_sockaddr_in_list(sockaddr_in_list ** head)
{
    char *token;

    while ((token = strtok(NULL, w_space))) {
        parse_sockaddr_in_list_token(head, token);
    }
}

static void
dump_sockaddr_in_list(StoreEntry * e, const char *n, const sockaddr_in_list * s)
{
    while (s) {
        storeAppendPrintf(e, "%s %s:%d\n",
                          n,
                          inet_ntoa(s->s.sin_addr),
                          ntohs(s->s.sin_port));
        s = s->next;
    }
}

static void
free_sockaddr_in_list(sockaddr_in_list ** head)
{
    sockaddr_in_list *s;

    while ((s = *head) != NULL) {
        *head = s->next;
        xfree(s);
    }
}

#if CURRENTLY_UNUSED
/* This code was previously used by http_port. Left as it really should
 * be used by icp_port and htcp_port
 */
static int
check_null_sockaddr_in_list(const sockaddr_in_list * s)
{
    return NULL == s;
}

#endif /* CURRENTLY_UNUSED */
#endif /* USE_WCCPv2 */

static void
parse_http_port_specification(http_port_list * s, char *token)
{
    char *host = NULL;

    const struct hostent *hp;
    unsigned short port = 0;
    char *t;

    s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
    s->name = xstrdup(token);

    if ((t = strchr(token, ':'))) {
        /* host:port */
        host = token;
        *t = '\0';
        port = xatos(t + 1);
    } else {
        /* port */
        port = xatos(token);
    }

    if (port == 0)
        self_destruct();

    s->s.sin_port = htons(port);

    if (NULL == host)
        s->s.sin_addr = any_addr;
    else if (1 == safe_inet_addr(host, &s->s.sin_addr))
        (void) 0;
    else if ((hp = gethostbyname(host))) {
        /* dont use ipcache */
        s->s.sin_addr = inaddrFromHostent(hp);
        s->defaultsite = xstrdup(host);
    } else
        self_destruct();
}

static void
parse_http_port_option(http_port_list * s, char *token)
{
    if (strncmp(token, "defaultsite=", 12) == 0) {
        safe_free(s->defaultsite);
        s->defaultsite = xstrdup(token + 12);
        s->accel = 1;
    } else if (strncmp(token, "name=", 5) == 0) {
        safe_free(s->name);
        s->name = xstrdup(token + 5);
    } else if (strcmp(token, "transparent") == 0) {
        s->transparent = 1;
    } else if (strcmp(token, "vhost") == 0) {
        s->vhost = 1;
        s->accel = 1;
    } else if (strcmp(token, "vport") == 0) {
        s->vport = -1;
        s->accel = 1;
    } else if (strncmp(token, "vport=", 6) == 0) {
        s->vport = xatos(token + 6);
        s->accel = 1;
    } else if (strncmp(token, "protocol=", 9) == 0) {
        s->protocol = xstrdup(token + 9);
        s->accel = 1;
    } else if (strcmp(token, "accel") == 0) {
        s->accel = 1;
    } else if (strncmp(token, "disable-pmtu-discovery=", 23) == 0) {
        if (!strcasecmp(token + 23, "off"))
            s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
        else if (!strcasecmp(token + 23, "transparent"))
            s->disable_pmtu_discovery = DISABLE_PMTU_TRANSPARENT;
        else if (!strcasecmp(token + 23, "always"))
            s->disable_pmtu_discovery = DISABLE_PMTU_ALWAYS;
        else
            self_destruct();

#if LINUX_TPROXY

    } else if (strcmp(token, "tproxy") == 0) {
        s->tproxy = 1;
        need_linux_tproxy = 1;
#endif

    } else {
        self_destruct();
    }
}

static void
free_generic_http_port_data(http_port_list * s)
{
    safe_free(s->name);
    safe_free(s->defaultsite);
    safe_free(s->protocol);
}

static void
cbdataFree_http_port(void *data)
{
    free_generic_http_port_data((http_port_list *)data);
}

static http_port_list *
create_http_port(char *portspec)
{
    CBDATA_TYPE(http_port_list);
    CBDATA_INIT_TYPE_FREECB(http_port_list, cbdataFree_http_port);

    http_port_list *s = cbdataAlloc(http_port_list);
    s->protocol = xstrdup("http");
    parse_http_port_specification(s, portspec);
    return s;
}

void
add_http_port(char *portspec)
{
    http_port_list *s = create_http_port(portspec);
    s->next = Config.Sockaddr.http;
    Config.Sockaddr.http = s;
}

static void
parse_http_port_list(http_port_list ** head)
{
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    http_port_list *s = create_http_port(token);

    /* parse options ... */
    while ((token = strtok(NULL, w_space))) {
        parse_http_port_option(s, token);
    }

    while (*head)
        head = &(*head)->next;

    *head = s;
}

static void
dump_generic_http_port(StoreEntry * e, const char *n, const http_port_list * s)
{
    storeAppendPrintf(e, "%s %s:%d",
                      n,
                      inet_ntoa(s->s.sin_addr),
                      ntohs(s->s.sin_port));

    if (s->defaultsite)
        storeAppendPrintf(e, " defaultsite=%s", s->defaultsite);

    if (s->transparent)
        storeAppendPrintf(e, " transparent");

    if (s->vhost)
        storeAppendPrintf(e, " vhost");

    if (s->vport)
        storeAppendPrintf(e, " vport");

    if (s->disable_pmtu_discovery != DISABLE_PMTU_OFF) {
        const char *pmtu;

        if (s->disable_pmtu_discovery == DISABLE_PMTU_ALWAYS)
            pmtu = "always";
        else
            pmtu = "transparent";

        storeAppendPrintf(e, " disable-pmtu-discovery=%s", pmtu);
    }
}

static void
dump_http_port_list(StoreEntry * e, const char *n, const http_port_list * s)
{
    while (s) {
        dump_generic_http_port(e, n, s);
        storeAppendPrintf(e, "\n");
        s = s->next;
    }
}

static void
free_http_port_list(http_port_list ** head)
{
    http_port_list *s;

    while ((s = *head) != NULL) {
        *head = s->next;
        cbdataFree(s);
    }
}

#if USE_SSL
static void
cbdataFree_https_port(void *data)
{
    https_port_list *s = (https_port_list *)data;
    free_generic_http_port_data(&s->http);
    safe_free(s->cert);
    safe_free(s->key);
    safe_free(s->options);
    safe_free(s->cipher);
    safe_free(s->cafile);
    safe_free(s->capath);
    safe_free(s->dhfile);
    safe_free(s->sslflags);
}

static void
parse_https_port_list(https_port_list ** head)
{
    CBDATA_TYPE(https_port_list);
    char *token;
    https_port_list *s;
    CBDATA_INIT_TYPE_FREECB(https_port_list, cbdataFree_https_port);
    token = strtok(NULL, w_space);

    if (!token)
        self_destruct();

    s = cbdataAlloc(https_port_list);

    s->http.protocol = xstrdup("https");

    parse_http_port_specification(&s->http, token);

    /* parse options ... */
    while ((token = strtok(NULL, w_space))) {
        if (strncmp(token, "cert=", 5) == 0) {
            safe_free(s->cert);
            s->cert = xstrdup(token + 5);
        } else if (strncmp(token, "key=", 4) == 0) {
            safe_free(s->key);
            s->key = xstrdup(token + 4);
        } else if (strncmp(token, "version=", 8) == 0) {
            s->version = xatoi(token + 8);

            if (s->version < 1 || s->version > 4)
                self_destruct();
        } else if (strncmp(token, "options=", 8) == 0) {
            safe_free(s->options);
            s->options = xstrdup(token + 8);
        } else if (strncmp(token, "cipher=", 7) == 0) {
            safe_free(s->cipher);
            s->cipher = xstrdup(token + 7);
        } else if (strncmp(token, "clientca=", 9) == 0) {
            safe_free(s->clientca);
            s->clientca = xstrdup(token + 9);
        } else if (strncmp(token, "cafile=", 7) == 0) {
            safe_free(s->cafile);
            s->cafile = xstrdup(token + 7);
        } else if (strncmp(token, "capath=", 7) == 0) {
            safe_free(s->capath);
            s->capath = xstrdup(token + 7);
        } else if (strncmp(token, "crlfile=", 8) == 0) {
            safe_free(s->crlfile);
            s->crlfile = xstrdup(token + 8);
        } else if (strncmp(token, "dhparams=", 9) == 0) {
            safe_free(s->dhfile);
            s->dhfile = xstrdup(token + 9);
        } else if (strncmp(token, "sslflags=", 9) == 0) {
            safe_free(s->sslflags);
            s->sslflags = xstrdup(token + 9);
        } else if (strncmp(token, "sslcontext=", 11) == 0) {
            safe_free(s->sslcontext);
            s->sslcontext = xstrdup(token + 11);
        } else {
            parse_http_port_option(&s->http, token);
        }
    }

    while (*head) {
        http_port_list ** headTmp = &(*head)->http.next;
        head = (https_port_list **)headTmp;
    }

    *head = s;
}

static void
dump_https_port_list(StoreEntry * e, const char *n, const https_port_list * s)
{
    while (s) {
        dump_generic_http_port(e, n, &s->http);

        if (s->cert)
            storeAppendPrintf(e, " cert=%s", s->cert);

        if (s->key)
            storeAppendPrintf(e, " key=%s", s->key);

        if (s->version)
            storeAppendPrintf(e, " version=%d", s->version);

        if (s->options)
            storeAppendPrintf(e, " options=%s", s->options);

        if (s->cipher)
            storeAppendPrintf(e, " cipher=%s", s->cipher);

        if (s->cafile)
            storeAppendPrintf(e, " cafile=%s", s->cafile);

        if (s->capath)
            storeAppendPrintf(e, " capath=%s", s->capath);

        if (s->crlfile)
            storeAppendPrintf(e, " crlfile=%s", s->crlfile);

        if (s->dhfile)
            storeAppendPrintf(e, " dhparams=%s", s->dhfile);

        if (s->sslflags)
            storeAppendPrintf(e, " sslflags=%s", s->sslflags);

        if (s->sslcontext)
            storeAppendPrintf(e, " sslcontext=%s", s->sslcontext);

        storeAppendPrintf(e, "\n");

        s = (https_port_list *) s->http.next;
    }
}

static void
free_https_port_list(https_port_list ** head)
{
    https_port_list *s;

    while ((s = *head) != NULL) {
        *head = (https_port_list *) s->http.next;
        cbdataFree(s);
    }
}

#if 0
static int
check_null_https_port_list(const https_port_list * s)
{
    return NULL == s;
}

#endif

#endif /* USE_SSL */

void
configFreeMemory(void)
{
    free_all();
}

void
requirePathnameExists(const char *name, const char *path)
{

    struct stat sb;
    char pathbuf[BUFSIZ];
    assert(path != NULL);

    if (Config.chroot_dir && (geteuid() == 0)) {
        snprintf(pathbuf, BUFSIZ, "%s/%s", Config.chroot_dir, path);
        path = pathbuf;
    }

    if (stat(path, &sb) < 0) {
        if (opt_send_signal == -1 || opt_send_signal == SIGHUP)
            fatalf("%s %s: %s", name, path, xstrerror());
        else
            fprintf(stderr, "WARNING: %s %s: %s\n", name, path, xstrerror());
    }
}

char *
strtokFile(void)
{
    return ConfigParser::strtokFile();
}

#include "AccessLogEntry.h"
/* TODO: split out parsing somehow ...*/
static void
parse_logformat(logformat ** logformat_definitions)
{
    logformat *nlf;
    char *name, *def;

    if ((name = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((def = strtok(NULL, "\r\n")) == NULL) {
        self_destruct();
        return;
    }

    debugs(3, 2, "Logformat for '" << name << "' is '" << def << "'");

    nlf = (logformat *)xcalloc(1, sizeof(logformat));

    nlf->name = xstrdup(name);

    if (!accessLogParseLogFormat(&nlf->format, def)) {
        self_destruct();
        return;
    }

    nlf->next = *logformat_definitions;

    *logformat_definitions = nlf;
}

static void
parse_access_log(customlog ** logs)
{
    const char *filename, *logdef_name;
    customlog *cl;
    logformat *lf;

    cl = (customlog *)xcalloc(1, sizeof(*cl));

    if ((filename = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(filename, "none") == 0) {
        cl->type = CLF_NONE;
        goto done;
    }

    if ((logdef_name = strtok(NULL, w_space)) == NULL)
        logdef_name = "auto";

    debugs(3, 9, "Log definition name '" << logdef_name << "' file '" << filename << "'");

    cl->filename = xstrdup(filename);

    /* look for the definition pointer corresponding to this name */
    lf = Config.Log.logformats;

    while (lf != NULL) {
        debugs(3, 9, "Comparing against '" << lf->name << "'");

        if (strcmp(lf->name, logdef_name) == 0)
            break;

        lf = lf->next;
    }

    if (lf != NULL) {
        cl->type = CLF_CUSTOM;
        cl->logFormat = lf;
    } else if (strcmp(logdef_name, "auto") == 0) {
        cl->type = CLF_AUTO;
    } else if (strcmp(logdef_name, "squid") == 0) {
        cl->type = CLF_SQUID;
    } else if (strcmp(logdef_name, "common") == 0) {
        cl->type = CLF_COMMON;
    } else {
        debugs(3, 0, "Log format '" << logdef_name << "' is not defined");
        self_destruct();
        return;
    }

done:
    aclParseAclList(LegacyParser, &cl->aclList);

    while (*logs)
        logs = &(*logs)->next;

    *logs = cl;
}

#if UNUSED_CODE
static int
check_null_access_log(customlog *customlog_definitions)
{
    return customlog_definitions == NULL;
}
#endif

static void
dump_logformat(StoreEntry * entry, const char *name, logformat * definitions)
{
    accessLogDumpLogFormat(entry, name, definitions);
}

static void
dump_access_log(StoreEntry * entry, const char *name, customlog * logs)
{
    customlog *log;

    for (log = logs; log; log = log->next) {
        storeAppendPrintf(entry, "%s ", name);

        switch (log->type) {

        case CLF_CUSTOM:
            storeAppendPrintf(entry, "%s %s", log->filename, log->logFormat->name);
            break;

        case CLF_NONE:
            storeAppendPrintf(entry, "none");
            break;

        case CLF_SQUID:
            storeAppendPrintf(entry, "%s squid", log->filename);
            break;

        case CLF_COMMON:
            storeAppendPrintf(entry, "%s squid", log->filename);
            break;

        case CLF_AUTO:

            if (log->aclList)
                storeAppendPrintf(entry, "%s auto", log->filename);
            else
                storeAppendPrintf(entry, "%s", log->filename);

            break;

        case CLF_UNKNOWN:
            break;
        }

        if (log->aclList)
            dump_acl_list(entry, log->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
free_logformat(logformat ** definitions)
{
    while (*definitions) {
        logformat *format = *definitions;
        *definitions = format->next;
        accessLogFreeLogFormat(&format->format);
        xfree(format);
    }
}

static void
free_access_log(customlog ** definitions)
{
    while (*definitions) {
        customlog *log = *definitions;
        *definitions = log->next;

        log->logFormat = NULL;
        log->type = CLF_UNKNOWN;

        if (log->aclList)
            aclDestroyAclList(&log->aclList);

        safe_free(log->filename);

        xfree(log);
    }
}

#if ICAP_CLIENT

static void
parse_icap_service_type(ICAPConfig * cfg)
{
    cfg->parseICAPService();
}

static void
free_icap_service_type(ICAPConfig * cfg)
{
    cfg->freeICAPService();
}

static void
dump_icap_service_type(StoreEntry * entry, const char *name, const ICAPConfig &cfg)
{
    cfg.dumpICAPService(entry, name);
}

static void
parse_icap_class_type(ICAPConfig * cfg)
{
    cfg->parseICAPClass();
}

static void
free_icap_class_type(ICAPConfig * cfg)
{
    cfg->freeICAPClass();
}

static void
dump_icap_class_type(StoreEntry * entry, const char *name, const ICAPConfig &cfg)
{
    cfg.dumpICAPClass(entry, name);
}

static void
parse_icap_access_type(ICAPConfig * cfg)
{
    cfg->parseICAPAccess(LegacyParser);
}

static void
free_icap_access_type(ICAPConfig * cfg)
{
    cfg->freeICAPAccess();
}

static void
dump_icap_access_type(StoreEntry * entry, const char *name, const ICAPConfig &cfg)
{
    cfg.dumpICAPAccess(entry, name);
}

#endif
