
/*
 * $Id: cache_cf.cc,v 1.434 2003/02/21 22:50:06 robertc Exp $
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
#include "Store.h"
#include "SwapDir.h"
#include "Config.h"
#include "ACL.h"

#if SQUID_SNMP
#include "snmp.h"
#endif

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

static void parse_cachedir_option_readonly(SwapDir * sd, const char *option, const char *value, int reconfiguring);
static void dump_cachedir_option_readonly(StoreEntry * e, const char *option, SwapDir const * sd);
static void parse_cachedir_option_maxsize(SwapDir * sd, const char *option, const char *value, int reconfiguring);
static void dump_cachedir_option_maxsize(StoreEntry * e, const char *option, SwapDir const * sd);

static struct cache_dir_option common_cachedir_options[] =
    {
        {"read-only", parse_cachedir_option_readonly, dump_cachedir_option_readonly},

        {"max-size", parse_cachedir_option_maxsize, dump_cachedir_option_maxsize},
        {NULL, NULL}
    };


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
#ifdef HTTP_VIOLATIONS
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
#if CURRENTLY_UNUSED
static void parse_sockaddr_in_list(sockaddr_in_list **);
static void dump_sockaddr_in_list(StoreEntry *, const char *, const sockaddr_in_list *);
static void free_sockaddr_in_list(sockaddr_in_list **);
static int check_null_sockaddr_in_list(const sockaddr_in_list *);
#endif /* CURRENTLY_UNUSED */
static void parse_http_port_list(http_port_list **);
static void dump_http_port_list(StoreEntry *, const char *, const http_port_list *);
static void free_http_port_list(http_port_list **);
#if UNUSED_CODE
static int check_null_http_port_list(const http_port_list *);
#endif
#if USE_SSL
static void parse_https_port_list(https_port_list **);
static void dump_https_port_list(StoreEntry *, const char *, const https_port_list *);
static void free_https_port_list(https_port_list **);
#if 0
static int check_null_https_port_list(const https_port_list *);
#endif
#endif /* USE_SSL */

void
self_destruct(void)
{
    fatalf("Bungled %s line %d: %s",
           cfg_filename, config_lineno, config_input_line);
}

void
wordlistDestroy(wordlist ** list)
{
    wordlist *w = NULL;

    while ((w = *list) != NULL) {
        *list = w->next;
        safe_free(w->key);
        memFree(w, MEM_WORDLIST);
    }

    *list = NULL;
}

const char *
wordlistAdd(wordlist ** list, const char *key)
{
    while (*list)
        list = &(*list)->next;

    *list = static_cast<wordlist *>(memAllocate(MEM_WORDLIST));

    (*list)->key = xstrdup(key);

    (*list)->next = NULL;

    return (*list)->key;
}

void
wordlistJoin(wordlist ** list, wordlist ** wl)
{
    while (*list)
        list = &(*list)->next;

    *list = *wl;

    *wl = NULL;
}

void
wordlistAddWl(wordlist ** list, wordlist * wl)
{
    while (*list)
        list = &(*list)->next;

    for (; wl; wl = wl->next, list = &(*list)->next) {
        *list = static_cast<wordlist *>(memAllocate(MEM_WORDLIST));
        (*list)->key = xstrdup(wl->key);
        (*list)->next = NULL;
    }
}

void
wordlistCat(const wordlist * w, MemBuf * mb)
{
    while (NULL != w) {
        memBufPrintf(mb, "%s\n", w->key);
        w = w->next;
    }
}

wordlist *
wordlistDup(const wordlist * w)
{
    wordlist *D = NULL;

    while (NULL != w) {
        wordlistAdd(&D, w->key);
        w = w->next;
    }

    return D;
}

void
intlistDestroy(intlist ** list)
{
    intlist *w = NULL;
    intlist *n = NULL;

    for (w = *list; w; w = n) {
        n = w->next;
        memFree(w, MEM_INTLIST);
    }

    *list = NULL;
}

int
intlistFind(intlist * list, int i)
{
    intlist *w = NULL;

    for (w = list; w; w = w->next)
        if (w->i == i)
            return 1;

    return 0;
}

/*
 * These functions is the same as atoi/l/f, except that they check for errors
 */

static long
xatol(const char *token)
{
    char *end;
    long ret = strtol(token, &end, 10);

    if (ret == 0 && end == token)
        self_destruct();

    return ret;
}

static int
xatoi(const char *token)
{
    return xatol(token);
}

static double
xatof(const char *token)
{
    char *end;
    double ret = strtod(token, &end);

    if (ret == 0 && end == token)
        self_destruct();

    return ret;
}

int
GetInteger(void)
{
    char *token = strtok(NULL, w_space);
    int i;

    if (token == NULL)
        self_destruct();

    if (sscanf(token, "%d", &i) != 1)
        self_destruct();

    return i;
}

static void
update_maxobjsize(void)
{
    int i;
    ssize_t ms = -1;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        assert (Config.cacheSwap.swapDirs[i]);

        if (Config.cacheSwap.swapDirs[i]->max_objsize > ms)
            ms = Config.cacheSwap.swapDirs[i]->max_objsize;
    }

    store_maxobjsize = ms;
}

int
parseConfigFile(const char *file_name)
{
    FILE *fp = NULL;
    char *token = NULL;
    char *tmp_line;
    int err_count = 0;
    int is_pipe = 0;
    configFreeMemory();
    default_all();

    if (file_name[0] == '!' || file_name[0] == '|') {
        fp = popen(file_name + 1, "r");
        is_pipe = 1;
    } else {
        fp = fopen(file_name, "r");
    }

    if (fp == NULL)
        fatalf("Unable to open configuration file: %s: %s",
               file_name, xstrerror());

#if defined(_SQUID_MSWIN_) || defined(_SQUID_CYGWIN_)

    setmode(fileno(fp), O_TEXT);

#endif

    cfg_filename = file_name;

    if (is_pipe)
        cfg_filename = file_name + 1;
    else if ((token = strrchr(cfg_filename, '/')))
        cfg_filename = token + 1;

    memset(config_input_line, '\0', BUFSIZ);

    config_lineno = 0;

    while (fgets(config_input_line, BUFSIZ, fp)) {
        config_lineno++;

        if ((token = strchr(config_input_line, '\n')))
            *token = '\0';

        if (strncmp(config_input_line, "#line ", 6) == 0) {
            static char new_file_name[1024];
            static char *file;
            static char new_lineno;
            token = config_input_line + 6;
            new_lineno = strtol(token, &file, 0) - 1;

            if (file == token)
                continue;	/* Not a valid #line directive, may be a comment */

            while (*file && isspace((unsigned char) *file))
                file++;

            if (*file) {
                if (*file != '"')
                    continue;	/* Not a valid #line directive, may be a comment */

                xstrncpy(new_file_name, file + 1, sizeof(new_file_name));

                if ((token = strchr(new_file_name, '"')))
                    *token = '\0';

                cfg_filename = new_file_name;

#if PROBABLY_NOT_WANTED_HERE

                if ((token = strrchr(cfg_filename, '/')))
                    cfg_filename = token + 1;

#endif

            }

            config_lineno = new_lineno;
        }

        if (config_input_line[0] == '#')
            continue;

        if (config_input_line[0] == '\0')
            continue;

        debug(3, 5) ("Processing: '%s'\n", config_input_line);

        tmp_line = xstrdup(config_input_line);

        if (!parse_line(tmp_line)) {
            debug(3, 0) ("parseConfigFile: '%s' line %d unrecognized: '%s'\n",
                         cfg_filename,
                         config_lineno,
                         config_input_line);
            err_count++;
        }

        safe_free(tmp_line);
    }

    if (is_pipe) {
        int ret = pclose(fp);

        if (ret != 0)
            fatalf("parseConfigFile: '%s' failed with exit code %d\n", file_name, ret);
    } else {
        fclose(fp);
    }

    defaults_if_none();
    configDoConfigure();
    cachemgrRegister("config",
                     "Current Squid Configuration",
                     dump_config,
                     1, 1);
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

    /* calculate Config.Swap.maxSize */
    storeDirConfigure();

    if (0 == Config.Swap.maxSize)
        /* people might want a zero-sized cache on purpose */
        (void) 0;
    else if (Config.Swap.maxSize < (Config.memMaxSize >> 10))
        debug(3, 0) ("WARNING cache_mem is larger than total disk cache space!\n");

    if (Config.Announce.period > 0) {
        Config.onoff.announce = 1;
    } else if (Config.Announce.period < 1) {
        Config.Announce.period = 86400 * 365;	/* one year */
        Config.onoff.announce = 0;
    }

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
             full_appname_string);

    /*
     * the extra space is for loop detection in client_side.c -- we search
     * for substrings in the Via header.
     */
    snprintf(ThisCache2, sizeof(ThisCache), " %s (%s)",
             uniqueHostname(),
             full_appname_string);

    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
        Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;

    if (Config.appendDomain)
        Config.appendDomainLen = strlen(Config.appendDomain);
    else
        Config.appendDomainLen = 0;

    safe_free(debug_options)
    debug_options = xstrdup(Config.debugOptions);

    if (Config.retry.timeout < 5)
        fatal("minimum_retry_timeout must be at least 5 seconds");

    if (Config.retry.maxtries > 10)
        fatal("maximum_single_addr_tries cannot be larger than 10");

    if (Config.retry.maxtries < 1) {
        debug(3, 0) ("WARNING: resetting 'maximum_single_addr_tries to 1\n");
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

            debug(22, 1) ("WARNING: use of 'override-expire' in 'refresh_pattern' violates HTTP\n");

            break;
        }

        for (R = Config.Refresh; R; R = R->next)
        {
            if (!R->flags.override_lastmod)
                continue;

            debug(22, 1) ("WARNING: use of 'override-lastmod' in 'refresh_pattern' violates HTTP\n");

            break;
        }

    }
#endif
#if !HTTP_VIOLATIONS
    Config.onoff.via = 1;
#else

    if (!Config.onoff.via)
        debug(22, 1) ("WARNING: HTTP requires the use of Via\n");

#endif

    if (Config.Wais.relayHost) {
        if (Config.Wais._peer)
            cbdataFree(Config.Wais._peer);

        Config.Wais._peer = cbdataAlloc(peer);

        Config.Wais._peer->host = xstrdup(Config.Wais.relayHost);

        Config.Wais._peer->http_port = Config.Wais.relayPort;
    }

    if (aclPurgeMethodInUse(Config.accessList.http))
        Config2.onoff.enable_purge = 1;

    if (geteuid() == 0) {
        if (NULL != Config.effectiveUser) {

            struct passwd *pwd = getpwnam(Config.effectiveUser);

            if (NULL == pwd)
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

            Config2.effectiveUserID = pwd->pw_uid;

            Config2.effectiveGroupID = pwd->pw_gid;
        }
    } else {
        Config2.effectiveUserID = geteuid();
        Config2.effectiveGroupID = getegid();
    }

    if (NULL != Config.effectiveGroup) {

        struct group *grp = getgrnam(Config.effectiveGroup);

        if (NULL == grp)
            fatalf("getgrnam failed to find groupid for effective group '%s'",
                   Config.effectiveGroup);

        Config2.effectiveGroupID = grp->gr_gid;
    }

    urlExtMethodConfigure();

    if (0 == Config.onoff.client_db) {
        acl *a;

        for (a = Config.aclList; a; a = a->next) {
            if (ACL_MAXCONN != a->aclType())
                continue;

            debug(22, 0) ("WARNING: 'maxconn' ACL (%s) won't work with client_db disabled\n", a->name);
        }
    }

#if USE_SSL
    Config.ssl_client.sslContext = sslCreateClientContext(Config.ssl_client.cert, Config.ssl_client.key, Config.ssl_client.version, Config.ssl_client.cipher, Config.ssl_client.options, Config.ssl_client.flags, Config.ssl_client.cafile, Config.ssl_client.capath);

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
        debug(3, 0) ("WARNING: No units on '%s', assuming %f %s\n",
                     config_input_line, d, units);
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

    debug(3, 1) ("parseTimeUnits: unknown time unit '%s'\n", unit);

    return 0;
}

static void
parseBytesLine(size_t * bptr, const char *units)
{
    char *token;
    double d;
    size_t m;
    size_t u;

    if ((u = parseBytesUnits(units)) == 0)
        self_destruct();

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debug(3, 0) ("WARNING: No units on '%s', assuming %f %s\n",
                     config_input_line, d, units);
    else if ((m = parseBytesUnits(token)) == 0)
        self_destruct();

    *bptr = static_cast<size_t>(m * d / u);
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

    debug(3, 1) ("parseBytesUnits: unknown bytes unit '%s'\n", unit);

    return 0;
}

/*****************************************************************************
 * Max
 *****************************************************************************/

static void
dump_acl(StoreEntry * entry, const char *name, acl * ae)
{
    wordlist *w;
    wordlist *v;

    while (ae != NULL) {
        debug(3, 3) ("dump_acl: %s %s\n", name, ae->name);
        storeAppendPrintf(entry, "%s %s %s ",
                          name,
                          ae->name,
                          ae->typeString());
        v = w = ae->dumpGeneric();

        while (v != NULL) {
            debug(3, 3) ("dump_acl: %s %s %s\n", name, ae->name, v->key);
            storeAppendPrintf(entry, "%s ", v->key);
            v = v->next;
        }

        storeAppendPrintf(entry, "\n");
        wordlistDestroy(&w);
        ae = ae->next;
    }
}

static void
parse_acl(acl ** ae)
{
    ACL::ParseAclLine(ae);
}

static void
free_acl(acl ** ae)
{
    aclDestroyAcls(ae);
}

static void
dump_acl_list(StoreEntry * entry, acl_list * head)
{
    acl_list *l;

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
    aclParseAccessLine(head);
}

static void
free_acl_access(acl_access ** head)
{
    aclDestroyAccessList(head);
}

static void

dump_address(StoreEntry * entry, const char *name, struct in_addr addr)
{
    storeAppendPrintf(entry, "%s %s\n", name, inet_ntoa(addr));
}

static void

parse_address(struct in_addr *addr)
{

    const struct hostent *hp;
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    if (safe_inet_addr(token, addr) == 1)
        (void) 0;
    else if ((hp = gethostbyname(token)))	/* dont use ipcache */
        *addr = inaddrFromHostent(hp);
    else
        self_destruct();
}

static void

free_address(struct in_addr *addr)
{

    memset(addr, '\0', sizeof(struct in_addr));
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
    aclParseAclList(&l->aclList);

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

    if (!token)
        self_destruct();

    if (sscanf(token, "0x%x%c", &tos, &junk) != 1)
        self_destruct();

    if (tos < 0 || tos > 255)
        self_destruct();

    CBDATA_INIT_TYPE_FREECB(acl_tos, freed_acl_tos);

    l = cbdataAlloc(acl_tos);

    l->tos = tos;

    aclParseAclList(&l->aclList);

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
    cfg->parsePoolAccess();
}

#endif

#ifdef HTTP_VIOLATIONS
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
        debug(3, 0) ("%s line %d: %s\n",
                     cfg_filename, config_lineno, config_input_line);
        debug(3, 0) ("parse_http_header_access: missing header name.\n");
        return;
    }

    /* Now lookup index of header. */
    id = httpHeaderIdByNameDef(t, strlen(t));

    if (strcmp(t, "All") == 0)
        id = HDR_ENUM_END;
    else if (strcmp(t, "Other") == 0)
        id = HDR_OTHER;
    else if (id == -1) {
        debug(3, 0) ("%s line %d: %s\n",
                     cfg_filename, config_lineno, config_input_line);
        debug(3, 0) ("parse_http_header_access: unknown header name %s.\n", t);
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
        debug(3, 0) ("%s line %d: %s\n",
                     cfg_filename, config_lineno, config_input_line);
        debug(3, 0) ("parse_http_header_replace: missing header name.\n");
        return;
    }

    /* Now lookup index of header. */
    id = httpHeaderIdByNameDef(t, strlen(t));

    if (strcmp(t, "All") == 0)
        id = HDR_ENUM_END;
    else if (strcmp(t, "Other") == 0)
        id = HDR_OTHER;
    else if (id == -1) {
        debug(3, 0) ("%s line %d: %s\n",
                     cfg_filename, config_lineno, config_input_line);
        debug(3, 0) ("parse_http_header_replace: unknown header name %s.\n",
                     t);
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

void

dump_cachedir_options(StoreEntry * entry, struct cache_dir_option *options, SwapDir const * sd)
{

    struct cache_dir_option *option;

    if (!options)
        return;

    for (option = options; option->name; option++)
        option->dump(entry, option->name, sd);
}

static void
dump_cachedir(StoreEntry * entry, const char *name, _SquidConfig::_cacheSwap swap)
{
    SwapDir *s;
    int i;
    assert (entry);

    for (i = 0; i < swap.n_configured; i++) {
        s = swap.swapDirs[i];
        storeAppendPrintf(entry, "%s %s %s", name, s->type, s->path);
        s->dump(*entry);
        dump_cachedir_options(entry, common_cachedir_options, s);
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
allocate_new_authScheme(authConfig * cfg)
{
    if (cfg->schemes == NULL) {
        cfg->n_allocated = 4;
        cfg->schemes = static_cast<authScheme *>(xcalloc(cfg->n_allocated, sizeof(authScheme)));
    }

    if (cfg->n_allocated == cfg->n_configured) {
        authScheme *tmp;
        cfg->n_allocated <<= 1;
        tmp = static_cast<authScheme *>(xcalloc(cfg->n_allocated, sizeof(authScheme)));
        xmemcpy(tmp, cfg->schemes, cfg->n_configured * sizeof(authScheme));
        xfree(cfg->schemes);
        cfg->schemes = tmp;
    }
}

static void
parse_authparam(authConfig * config)
{
    char *type_str;
    char *param_str;
    authScheme *scheme = NULL;
    int type, i;

    if ((type_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((param_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((type = authenticateAuthSchemeId(type_str)) == -1) {
        debug(3, 0) ("Parsing Config File: Unknown authentication scheme '%s'.\n", type_str);
        return;
    }

    for (i = 0; i < config->n_configured; i++) {
        if (config->schemes[i].Id == type) {
            scheme = config->schemes + i;
        }
    }

    if (scheme == NULL) {
        allocate_new_authScheme(config);
        scheme = config->schemes + config->n_configured;
        config->n_configured++;
        scheme->Id = type;
        scheme->typestr = authscheme_list[type].typestr;
    }

    authscheme_list[type].parse(scheme, config->n_configured, param_str);
}

static void
free_authparam(authConfig * cfg)
{
    authScheme *scheme;
    int i;
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    for (i = 0; i < cfg->n_configured; i++) {
        scheme = cfg->schemes + i;
        authscheme_list[scheme->Id].freeconfig(scheme);
    }

    safe_free(cfg->schemes);
    cfg->schemes = NULL;
    cfg->n_allocated = 0;
    cfg->n_configured = 0;
}

static void
dump_authparam(StoreEntry * entry, const char *name, authConfig cfg)
{
    authScheme *scheme;
    int i;

    for (i = 0; i < cfg.n_configured; i++) {
        scheme = cfg.schemes + i;
        authscheme_list[scheme->Id].dump(entry, name, scheme);
    }
}

void
allocate_new_swapdir(_SquidConfig::_cacheSwap * swap)
{
    if (swap->swapDirs == NULL) {
        swap->n_allocated = 4;
        swap->swapDirs = static_cast<SwapDir **>(xcalloc(swap->n_allocated, sizeof(SwapDir *)));
    }

    if (swap->n_allocated == swap->n_configured) {
        SwapDir **tmp;
        swap->n_allocated <<= 1;
        tmp = static_cast<SwapDir **>(xcalloc(swap->n_allocated, sizeof(SwapDir *)));
        xmemcpy(tmp, swap->swapDirs, swap->n_configured * sizeof(SwapDir *));
        xfree(swap->swapDirs);
        swap->swapDirs = tmp;
    }
}

static int
find_fstype(char *type)
{
    int i;

    for (i = 0; storefs_list[i].typestr != NULL; i++) {
        if (strcasecmp(type, storefs_list[i].typestr) == 0) {
            return i;
        }
    }

    return (-1);
}

static void
parse_cachedir(_SquidConfig::_cacheSwap * swap)
{
    char *type_str;
    char *path_str;
    SwapDir *sd;
    int i;
    int fs;

    if ((type_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((path_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    /*
     * This bit of code is a little strange.
     * See, if we find a path and type match for a given line, then
     * as long as we're reconfiguring, we can just call its reconfigure
     * function. No harm there.
     *
     * Trouble is, if we find a path match, but not a type match, we have
     * a dilemma - we could gracefully shut down the fs, kill it, and
     * create a new one of a new type in its place, BUT at this stage the
     * fs is meant to be the *NEW* one, and so things go very strange. :-)
     *
     * So, we'll assume the person isn't going to change the fs type for now,
     * and XXX later on we will make sure that its picked up.
     *
     * (moving around cache_dir lines will be looked at later in a little
     * more sane detail..)
     */

    for (i = 0; i < swap->n_configured; i++) {
        assert (swap->swapDirs[i]);

        if (0 == strcasecmp(path_str, swap->swapDirs[i]->path)) {
            /* This is a little weird, you'll appreciate it later */
            fs = find_fstype(type_str);

            if (fs < 0) {
                fatalf("Unknown cache_dir type '%s'\n", type_str);
            }

            sd = swap->swapDirs[i];
            sd->reconfigure (i, path_str);
            update_maxobjsize();
            return;
        }
    }

    assert(swap->n_configured < 63);	/* 7 bits, signed */

    fs = find_fstype(type_str);

    if (fs < 0) {
        /* If we get here, we didn't find a matching cache_dir type */
        fatalf("Unknown cache_dir type '%s'\n", type_str);
    }

    allocate_new_swapdir(swap);
    swap->swapDirs[swap->n_configured] = SwapDir::Factory(storefs_list[fs]);
    sd = swap->swapDirs[swap->n_configured];
    /* parse the FS parameters and options */
    sd->parse(swap->n_configured, path_str);
    ++swap->n_configured;
    /* Update the max object size */
    update_maxobjsize();
}

static void
parse_cachedir_option_readonly(SwapDir * sd, const char *option, const char *value, int reconfiguring)
{
    int read_only = 0;

    if (value)
        read_only = xatoi(value);
    else
        read_only = 1;

    sd->flags.read_only = read_only;
}

static void
dump_cachedir_option_readonly(StoreEntry * e, const char *option, SwapDir const * sd)
{
    if (sd->flags.read_only)
        storeAppendPrintf(e, " %s", option);
}

static void
parse_cachedir_option_maxsize(SwapDir * sd, const char *option, const char *value, int reconfiguring)
{
    ssize_t size;

    if (!value)
        self_destruct();

    size = xatoi(value);

    if (reconfiguring && sd->max_objsize != size)
        debug(3, 1) ("Cache dir '%s' max object size now %ld\n", sd->path, (long int) size);

    sd->max_objsize = size;
}

static void
dump_cachedir_option_maxsize(StoreEntry * e, const char *option, SwapDir const * sd)
{
    if (sd->max_objsize != -1)
        storeAppendPrintf(e, " %s=%ld", option, (long int) sd->max_objsize);
}

void

parse_cachedir_options(SwapDir * sd, struct cache_dir_option *options, int reconfiguring)
{
    unsigned int old_read_only = sd->flags.read_only;
    char *name, *value;

    struct cache_dir_option *option, *op;

    while ((name = strtok(NULL, w_space)) != NULL)
    {
        value = strchr(name, '=');

        if (value)
            *value++ = '\0';	/* cut on = */

        option = NULL;

        if (options) {
            for (op = options; !option && op->name; op++) {
                if (strcmp(op->name, name) == 0) {
                    option = op;
                    break;
                }
            }
        }

        for (op = common_cachedir_options; !option && op->name; op++) {
            if (strcmp(op->name, name) == 0) {
                option = op;
                break;
            }
        }

        if (!option || !option->parse)
            self_destruct();

        option->parse(sd, name, value, reconfiguring);
    }

    /*
     * Handle notifications about reconfigured single-options with no value
     * where the removal of the option cannot be easily detected in the
     * parsing...
     */
    if (reconfiguring)
    {
        if (old_read_only != sd->flags.read_only) {
            debug(3, 1) ("Cache dir '%s' now %s\n",
                         sd->path, sd->flags.read_only ? "Read-Only" : "Read-Write");
        }
    }
}

static void
free_cachedir(_SquidConfig::_cacheSwap * swap)
{
    int i;
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    for (i = 0; i < swap->n_configured; i++) {
        SwapDir * s = swap->swapDirs[i];
        swap->swapDirs[i] = NULL;
        delete s;
    }

    safe_free(swap->swapDirs);
    swap->swapDirs = NULL;
    swap->n_allocated = 0;
    swap->n_configured = 0;
}

static const char *
peer_type_str(const peer_t type)
{
    switch (type) {

    case PEER_PARENT:
        return "parent";
        break;

    case PEER_SIBLING:
        return "sibling";
        break;

    case PEER_MULTICAST:
        return "multicast";
        break;

    default:
        return "unknown";
        break;
    }
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

static void
parse_peer(peer ** head)
{
    char *token = NULL;
    peer *p;
    int i;
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

    i = GetInteger();

    p->http_port = (u_short) i;

    i = GetInteger();

    p->icp.port = (u_short) i;

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
            p->sslcipher = xstrdup(token + 10);
        } else if (strncmp(token, "sslcapath=", 10) == 0) {
            safe_free(p->sslcapath);
            p->sslcipher = xstrdup(token + 10);
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
            debug(3, 0) ("parse_peer: token='%s'\n", token);
            self_destruct();
        }
    }

    if (peerFindByName(p->name))
        fatalf("ERROR: cache_peer %s specified twice\n", p->name);

    if (p->weight < 1)
        p->weight = 1;

    p->icp.version = ICP_VERSION_CURRENT;

    p->tcp_up = PEER_TCP_MAGIC_COUNT;

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
#if USE_SSL
    if (p->use_ssl) {
        p->sslContext = sslCreateClientContext(p->sslcert, p->sslkey, p->sslversion, p->sslcipher, p->ssloptions, p->sslflags, p->sslcafile, p->sslcapath);
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

                debug(0, 0) ("WARNING: action '%s' (line %d) already has a password\n",
                             u->key, config_lineno);
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
        debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
                      cfg_filename, config_lineno, host);
        return;
    }

    aclParseAccessLine(&p->access);
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
            debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
                          cfg_filename, config_lineno, host);
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
            debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
                          cfg_filename, config_lineno, host);
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

#if UNUSED_CODE
static void
dump_ushortlist(StoreEntry * entry, const char *name, ushortlist * u)
{
    while (u) {
        storeAppendPrintf(entry, "%s %d\n", name, (int) u->i);
        u = u->next;
    }
}

static int
check_null_ushortlist(ushortlist * u)
{
    return u == NULL;
}

static void
parse_ushortlist(ushortlist ** P)
{
    char *token;
    int i;
    ushortlist *u;
    ushortlist **U;

    while ((token = strtok(NULL, w_space))) {
        if (sscanf(token, "%d", &i) != 1)
            self_destruct();

        if (i < 0)
            i = 0;

        u = xcalloc(1, sizeof(ushortlist));

        u->i = (u_short) i;

        for (U = P; *U; U = &(*U)->next)

            ;
        *U = u;
    }
}

static void
free_ushortlist(ushortlist ** P)
{
    ushortlist *u;

    while ((u = *P) != NULL) {
        *P = u->next;
        xfree(u);
    }
}

#endif

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
#define dump_eol dump_string
#define free_eol free_string

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
#if HTTP_VIOLATIONS

        if (head->flags.override_expire)
            storeAppendPrintf(entry, " override-expire");

        if (head->flags.override_lastmod)
            storeAppendPrintf(entry, " override-lastmod");

        if (head->flags.reload_into_ims)
            storeAppendPrintf(entry, " reload-into-ims");

        if (head->flags.ignore_reload)
            storeAppendPrintf(entry, " ignore-reload");

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
#if HTTP_VIOLATIONS

    int override_expire = 0;
    int override_lastmod = 0;
    int reload_into_ims = 0;
    int ignore_reload = 0;
#endif

    int i;
    refresh_t *t;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if (strcmp(token, "-i") == 0) {
        flags |= REG_ICASE;
        token = strtok(NULL, w_space);
    } else if (strcmp(token, "+i") == 0) {
        flags &= ~REG_ICASE;
        token = strtok(NULL, w_space);
    }

    if (token == NULL)
        self_destruct();

    pattern = xstrdup(token);

    i = GetInteger();		/* token: min */

    min = (time_t) (i * 60);	/* convert minutes to seconds */

    i = GetInteger();		/* token: pct */

    pct = (double) i / 100.0;

    i = GetInteger();		/* token: max */

    max = (time_t) (i * 60);	/* convert minutes to seconds */

    /* Options */
    while ((token = strtok(NULL, w_space)) != NULL) {
#if HTTP_VIOLATIONS

        if (!strcmp(token, "override-expire"))
            override_expire = 1;
        else if (!strcmp(token, "override-lastmod"))
            override_lastmod = 1;
        else if (!strcmp(token, "reload-into-ims")) {
            reload_into_ims = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
        } else if (!strcmp(token, "ignore-reload")) {
            ignore_reload = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
        } else
#endif

            debug(22, 0) ("redreshAddToList: Unknown option '%s': %s\n",
                          pattern, token);
    }

    if ((errcode = regcomp(&comp, pattern, flags)) != 0) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        debug(22, 0) ("%s line %d: %s\n",
                      cfg_filename, config_lineno, config_input_line);
        debug(22, 0) ("refreshAddToList: Invalid regular expression '%s': %s\n",
                      pattern, errbuf);
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

#if HTTP_VIOLATIONS

    if (override_expire)
        t->flags.override_expire = 1;

    if (override_lastmod)
        t->flags.override_lastmod = 1;

    if (reload_into_ims)
        t->flags.reload_into_ims = 1;

    if (ignore_reload)
        t->flags.ignore_reload = 1;

#endif

    t->next = NULL;

    while (*head)
        head = &(*head)->next;

    *head = t;

    safe_free(pattern);
}

#if UNUSED_CODE
static int
check_null_refreshpattern(refresh_t * data)
{
    return data == NULL;
}

#endif

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

    if (token == NULL)
        self_destruct();

    while (*token && isspace(*token))
        token++;

    if (!*token)
        self_destruct();

    *var = xstrdup((char *) token);
}

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

static void
dump_kb_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_KBYTES_STR);
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

CBDATA_TYPE(body_size);

static void
parse_body_size_t(dlink_list * bodylist)
{
    body_size *bs;
    CBDATA_INIT_TYPE(body_size);
    bs = cbdataAlloc(body_size);
    parse_size_t(&bs->maxsize);
    aclParseAccessLine(&bs->access_list);

    dlinkAddTail(bs, &bs->node, bodylist);
}

static void
dump_body_size_t(StoreEntry * entry, const char *name, dlink_list bodylist)
{
    body_size *bs;
    bs = (body_size *) bodylist.head;

    while (bs) {
        acl_list *l;
        acl_access *head = bs->access_list;

        while (head != NULL) {
            storeAppendPrintf(entry, "%s %ld %s", name, (long int) bs->maxsize,
                              head->allow ? "Allow" : "Deny");

            for (l = head->aclList; l != NULL; l = l->next) {
                storeAppendPrintf(entry, " %s%s",
                                  l->op ? null_string : "!",
                                  l->_acl->name);
            }

            storeAppendPrintf(entry, "\n");
            head = head->next;
        }

        bs = (body_size *) bs->node.next;
    }
}

static void
free_body_size_t(dlink_list * bodylist)
{
    body_size *bs, *tempnode;
    bs = (body_size *) bodylist->head;

    while (bs) {
        bs->maxsize = 0;
        aclDestroyAccessList(&bs->access_list);
        tempnode = (body_size *) bs->node.next;
        dlinkDelete(&bs->node, bodylist);
        cbdataFree(bs);
        bs = tempnode;
    }
}

static int
check_null_body_size_t(dlink_list bodylist)
{
    return bodylist.head == NULL;
}


static void
parse_kb_size_t(size_t * var)
{
    parseBytesLine(var, B_KBYTES_STR);
}

static void
free_size_t(size_t * var)
{
    *var = 0;
}

#define free_b_size_t free_size_t
#define free_kb_size_t free_size_t
#define free_mb_size_t free_size_t
#define free_gb_size_t free_size_t

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
    int i;

    i = GetInteger();

    if (i < 0)
        i = 0;

    *var = (u_short) i;
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

    xfree(*settings);

    *settings = NULL;
}

static void
parse_removalpolicy(RemovalPolicySettings ** settings)
{
    if (*settings)
        free_removalpolicy(settings);

    *settings = static_cast<RemovalPolicySettings *>(xcalloc(1, sizeof(**settings)));

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

    debug(15, 0) ("WARNING: Unknown neighbor type: %s\n", s);

    return PEER_SIBLING;
}

#if CURRENTLY_UNUSED
/* This code was previously used by http_port. Left as it really should
 * be used by icp_port and htcp_port
 */
void
parse_sockaddr_in_list_token(sockaddr_in_list ** head, char *token)
{
    char *t;
    char *host;

    const struct hostent *hp;
    unsigned short port;
    sockaddr_in_list *s;

    host = NULL;
    port = 0;

    if ((t = strchr(token, ':'))) {
        /* host:port */
        host = token;
        *t = '\0';
        port = (unsigned short) xatoi(t + 1);

        if (0 == port)
            self_destruct();
    } else if ((port = xatoi(token)) > 0) {
        /* port */
    } else {
        self_destruct();
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

static int
check_null_sockaddr_in_list(const sockaddr_in_list * s)
{
    return NULL == s;
}

#endif /* CURRENTLY_UNUSED */

static void
parse_http_port_specification(http_port_list * s, char *token)
{
    char *host = NULL;

    const struct hostent *hp;
    unsigned short port = 0;
    char *t;

    if ((t = strchr(token, ':'))) {
        /* host:port */
        host = token;
        *t = '\0';
        port = (unsigned short) atoi(t + 1);

        if (0 == port)
            self_destruct();
    } else if ((port = atoi(token)) > 0) {
        /* port */
    } else {
        self_destruct();
    }

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
        s->vport = atoi(token + 6);
        s->accel = 1;
    } else if (strncmp(token, "protocol=", 9) == 0) {
        s->protocol = xstrdup(token + 9);
        s->accel = 1;
    } else if (strcmp(token, "accel") == 0) {
        s->accel = 1;
    } else {
        self_destruct();
    }
}

static void
free_generic_http_port_data(http_port_list * s)
{
    safe_free(s->name);
    safe_free(s->defaultsite);
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

    if (!token)
        self_destruct();

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

#if UNUSED_CODE
static int
check_null_http_port_list(const http_port_list * s)
{
    return NULL == s;
}

#endif

#if USE_SSL
static void
cbdataFree_https_port(void *data)
{
    https_port_list *s = (https_port_list *)data;
    free_generic_http_port_data(&s->http);
    safe_free(s->cert);
    safe_free(s->key);
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
        } else if (strncmp(token, "sslflags=", 9) == 0) {
            safe_free(s->sslflags);
            s->sslflags = xstrdup(token + 9);
        } else {
            parse_http_port_option(&s->http, token);
        }
    }

    s->sslContext = sslCreateServerContext(s->cert, s->key, s->version, s->cipher, s->options, s->sslflags, s->clientca, s->cafile, s->capath);

    if (!s->sslContext)
        self_destruct();

    while (*head)
        head = (https_port_list **)&(*head)->http.next;

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
            storeAppendPrintf(e, " key=%s", s->cert);

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

        if (s->sslflags)
            storeAppendPrintf(e, " sslflags=%s", s->sslflags);

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

    if (Config.chroot_dir) {
        snprintf(pathbuf, BUFSIZ, "%s/%s", Config.chroot_dir, path);
        path = pathbuf;
    }

    if (stat(path, &sb) < 0)
        fatalf("%s %s: %s", name, path, xstrerror());
}

char *
strtokFile(void)
{
    static int fromFile = 0;
    static FILE *wordFile = NULL;

    char *t, *fn;
    LOCAL_ARRAY(char, buf, 256);

strtok_again:

    if (!fromFile) {
        t = (strtok(NULL, w_space));

        if (!t || *t == '#') {
            return NULL;
        } else if (*t == '\"' || *t == '\'') {
            /* quote found, start reading from file */
            fn = ++t;

            while (*t && *t != '\"' && *t != '\'')
                t++;

            *t = '\0';

            if ((wordFile = fopen(fn, "r")) == NULL) {
                debug(28, 0) ("strtokFile: %s not found\n", fn);
                return (NULL);
            }

#if defined(_SQUID_MSWIN_) || defined(_SQUID_CYGWIN_)
            setmode(fileno(wordFile), O_TEXT);

#endif

            fromFile = 1;
        } else {
            return t;
        }
    }

    /* fromFile */
    if (fgets(buf, 256, wordFile) == NULL) {
        /* stop reading from file */
        fclose(wordFile);
        wordFile = NULL;
        fromFile = 0;
        goto strtok_again;
    } else {
        char *t2, *t3;
        t = buf;
        /* skip leading and trailing white space */
        t += strspn(buf, w_space);
        t2 = t + strcspn(t, w_space);
        t3 = t2 + strspn(t2, w_space);

        while (*t3 && *t3 != '#') {
            t2 = t3 + strcspn(t3, w_space);
            t3 = t2 + strspn(t2, w_space);
        }

        *t2 = '\0';
        /* skip comments */

        if (*t == '#')
            goto strtok_again;

        /* skip blank lines */
        if (!*t)
            goto strtok_again;

        return t;
    }
}
