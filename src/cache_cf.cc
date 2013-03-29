/*
 * DEBUG: section 03    Configuration File Parsing
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
#include "acl/Acl.h"
#include "acl/AclAddress.h"
#include "acl/AclDenyInfoList.h"
#include "acl/AclNameList.h"
#include "acl/AclSizeLimit.h"
#include "acl/Gadgets.h"
#include "acl/MethodData.h"
#include "anyp/PortCfg.h"
#include "AuthReg.h"
#include "base/RunnersRegistry.h"
#include "mgr/ActionPasswordList.h"
#include "CachePeer.h"
#include "CachePeerDomainList.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "CpuAffinityMap.h"
#include "DiskIO/DiskIOModule.h"
#include "eui/Config.h"
#include "ExternalACL.h"
#include "format/Format.h"
#include "globals.h"
#include "HttpHeaderTools.h"
#include "HttpRequestMethod.h"
#include "ident/Config.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "ipc/Kids.h"
#include "log/Config.h"
#include "log/CustomLog.h"
#include "Mem.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "NeighborTypeDomainList.h"
#include "Parsing.h"
#include "PeerDigest.h"
#include "RefreshPattern.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "ssl/ProxyCerts.h"
#include "Store.h"
#include "StoreFileSystem.h"
#include "SwapDir.h"
#include "wordlist.h"
#include "neighbors.h"
#include "tools.h"
/* wccp2 has its own conditional definitions */
#include "wccp2.h"
#if USE_ADAPTATION
#include "adaptation/Config.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/Config.h"
#endif
#if USE_ECAP
#include "adaptation/ecap/Config.h"
#endif
#if USE_SSL
#include "ssl/support.h"
#include "ssl/Config.h"
#endif
#if USE_AUTH
#include "auth/Config.h"
#include "auth/Scheme.h"
#endif
#if USE_SQUID_ESI
#include "esi/Parser.h"
#endif
#if SQUID_SNMP
#include "snmp.h"
#endif

#if HAVE_GLOB_H
#include <glob.h>
#endif
#if HAVE_LIMITS_H
#include <limits>
#endif
#if HAVE_LIST
#include <list>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if USE_SSL
#include "ssl/gadgets.h"
#endif

#if USE_ADAPTATION
static void parse_adaptation_service_set_type();
static void parse_adaptation_service_chain_type();
static void parse_adaptation_access_type();
static void parse_adaptation_meta_type(Adaptation::Config::MetaHeaders *);
static void dump_adaptation_meta_type(StoreEntry *, const char *, Adaptation::Config::MetaHeaders &);
static void free_adaptation_meta_type(Adaptation::Config::MetaHeaders *);
#endif

#if ICAP_CLIENT
static void parse_icap_service_type(Adaptation::Icap::Config *);
static void dump_icap_service_type(StoreEntry *, const char *, const Adaptation::Icap::Config &);
static void free_icap_service_type(Adaptation::Icap::Config *);
static void parse_icap_class_type();
static void parse_icap_access_type();

static void parse_icap_service_failure_limit(Adaptation::Icap::Config *);
static void dump_icap_service_failure_limit(StoreEntry *, const char *, const Adaptation::Icap::Config &);
static void free_icap_service_failure_limit(Adaptation::Icap::Config *);
#endif

#if USE_ECAP
static void parse_ecap_service_type(Adaptation::Ecap::Config *);
static void dump_ecap_service_type(StoreEntry *, const char *, const Adaptation::Ecap::Config &);
static void free_ecap_service_type(Adaptation::Ecap::Config *);
#endif

static peer_t parseNeighborType(const char *s);

CBDATA_TYPE(CachePeer);

static const char *const T_MILLISECOND_STR = "millisecond";
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

static void parse_access_log(CustomLog ** customlog_definitions);
static int check_null_access_log(CustomLog *customlog_definitions);
static void dump_access_log(StoreEntry * entry, const char *name, CustomLog * definitions);
static void free_access_log(CustomLog ** definitions);

static void update_maxobjsize(void);
static void configDoConfigure(void);
static void parse_refreshpattern(RefreshPattern **);
static uint64_t parseTimeUnits(const char *unit,  bool allowMsec);
static void parseTimeLine(time_msec_t * tptr, const char *units, bool allowMsec);
static void parse_u_short(unsigned short * var);
static void parse_string(char **);
static void default_all(void);
static void defaults_if_none(void);
static void defaults_postscriptum(void);
static int parse_line(char *);
static void parse_obsolete(const char *);
static void parseBytesLine(size_t * bptr, const char *units);
#if USE_SSL
static void parseBytesOptionValue(size_t * bptr, const char *units, char const * value);
#endif
#if !USE_DNSHELPER
static void parseBytesLineSigned(ssize_t * bptr, const char *units);
#endif
static size_t parseBytesUnits(const char *unit);
static void free_all(void);
void requirePathnameExists(const char *name, const char *path);
static OBJH dump_config;
#if USE_HTTP_VIOLATIONS
static void free_HeaderManglers(HeaderManglers **pm);
static void dump_http_header_access(StoreEntry * entry, const char *name, const HeaderManglers *manglers);
static void parse_http_header_access(HeaderManglers **manglers);
#define free_http_header_access free_HeaderManglers
static void dump_http_header_replace(StoreEntry * entry, const char *name, const HeaderManglers *manglers);
static void parse_http_header_replace(HeaderManglers **manglers);
#define free_http_header_replace free_HeaderManglers
#endif
static void dump_HeaderWithAclList(StoreEntry * entry, const char *name, HeaderWithAclList *headers);
static void parse_HeaderWithAclList(HeaderWithAclList **header);
static void free_HeaderWithAclList(HeaderWithAclList **header);
static void parse_denyinfo(AclDenyInfoList ** var);
static void dump_denyinfo(StoreEntry * entry, const char *name, AclDenyInfoList * var);
static void free_denyinfo(AclDenyInfoList ** var);

#if USE_WCCPv2
static void parse_IpAddress_list(Ip::Address_list **);
static void dump_IpAddress_list(StoreEntry *, const char *, const Ip::Address_list *);
static void free_IpAddress_list(Ip::Address_list **);
#if CURRENTLY_UNUSED
static int check_null_IpAddress_list(const Ip::Address_list *);
#endif /* CURRENTLY_UNUSED */
#endif /* USE_WCCPv2 */

static void parsePortCfg(AnyP::PortCfg **, const char *protocol);
#define parse_PortCfg(l) parsePortCfg((l), token)
static void dump_PortCfg(StoreEntry *, const char *, const AnyP::PortCfg *);
static void free_PortCfg(AnyP::PortCfg **);

#if USE_SSL
static void parse_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign);
static void dump_sslproxy_cert_sign(StoreEntry *entry, const char *name, sslproxy_cert_sign *cert_sign);
static void free_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign);
static void parse_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt);
static void dump_sslproxy_cert_adapt(StoreEntry *entry, const char *name, sslproxy_cert_adapt *cert_adapt);
static void free_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt);
static void parse_sslproxy_ssl_bump(acl_access **ssl_bump);
static void dump_sslproxy_ssl_bump(StoreEntry *entry, const char *name, acl_access *ssl_bump);
static void free_sslproxy_ssl_bump(acl_access **ssl_bump);
#endif /* USE_SSL */

static void parse_b_size_t(size_t * var);
static void parse_b_int64_t(int64_t * var);

static bool parseNamedIntList(const char *data, const String &name, Vector<int> &list);

static void parse_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap);
static void dump_CpuAffinityMap(StoreEntry *const entry, const char *const name, const CpuAffinityMap *const cpuAffinityMap);
static void free_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap);

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
    int64_t ms = -1;

    // determine the maximum size object that can be stored to disk
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        assert (Config.cacheSwap.swapDirs[i].getRaw());

        const int64_t storeMax = dynamic_cast<SwapDir *>(Config.cacheSwap.swapDirs[i].getRaw())->maxObjectSize();
        if (ms < storeMax)
            ms = storeMax;
    }

    // Ensure that we do not discard objects which could be stored only in memory.
    // It is governed by maximum_object_size_in_memory (for now)
    // TODO: update this to check each in-memory location (SMP and local memory limits differ)
    if (ms < static_cast<int64_t>(Config.Store.maxInMemObjSize))
        ms = Config.Store.maxInMemObjSize;

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
    for (i = 0; i < (int)globbuf.gl_pathc; ++i) {
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

static void
ReplaceSubstr(char*& str, int& len, unsigned substrIdx, unsigned substrLen, const char* newSubstr)
{
    assert(str != NULL);
    assert(newSubstr != NULL);

    unsigned newSubstrLen = strlen(newSubstr);
    if (newSubstrLen > substrLen)
        str = (char*)realloc(str, len - substrLen + newSubstrLen + 1);

    // move tail part including zero
    memmove(str + substrIdx + newSubstrLen, str + substrIdx + substrLen, len - substrIdx - substrLen + 1);
    // copy new substring in place
    memcpy(str + substrIdx, newSubstr, newSubstrLen);

    len = strlen(str);
}

static void
SubstituteMacro(char*& line, int& len, const char* macroName, const char* substStr)
{
    assert(line != NULL);
    assert(macroName != NULL);
    assert(substStr != NULL);
    unsigned macroNameLen = strlen(macroName);
    while (const char* macroPos = strstr(line, macroName)) // we would replace all occurrences
        ReplaceSubstr(line, len, macroPos - line, macroNameLen, substStr);
}

static void
ProcessMacros(char*& line, int& len)
{
    SubstituteMacro(line, len, "${process_name}", TheKidName);
    SubstituteMacro(line, len, "${process_number}", xitoa(KidIdentifier));
}

static void
trim_trailing_ws(char* str)
{
    assert(str != NULL);
    unsigned i = strlen(str);
    while ((i > 0) && xisspace(str[i - 1]))
        --i;
    str[i] = '\0';
}

static const char*
FindStatement(const char* line, const char* statement)
{
    assert(line != NULL);
    assert(statement != NULL);

    const char* str = skip_ws(line);
    unsigned len = strlen(statement);
    if (strncmp(str, statement, len) == 0) {
        str += len;
        if (*str == '\0')
            return str;
        else if (xisspace(*str))
            return skip_ws(str);
    }

    return NULL;
}

static bool
StrToInt(const char* str, long& number)
{
    assert(str != NULL);

    char* end;
    number = strtol(str, &end, 0);

    return (end != str) && (*end == '\0'); // returns true if string contains nothing except number
}

static bool
EvalBoolExpr(const char* expr)
{
    assert(expr != NULL);
    if (strcmp(expr, "true") == 0) {
        return true;
    } else if (strcmp(expr, "false") == 0) {
        return false;
    } else if (const char* equation = strchr(expr, '=')) {
        const char* rvalue = skip_ws(equation + 1);
        char* lvalue = (char*)xmalloc(equation - expr + 1);
        xstrncpy(lvalue, expr, equation - expr + 1);
        trim_trailing_ws(lvalue);

        long number1;
        if (!StrToInt(lvalue, number1))
            fatalf("String is not a integer number: '%s'\n", lvalue);
        long number2;
        if (!StrToInt(rvalue, number2))
            fatalf("String is not a integer number: '%s'\n", rvalue);

        xfree(lvalue);
        return number1 == number2;
    }
    fatalf("Unable to evaluate expression '%s'\n", expr);
    return false; // this place cannot be reached
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

    debugs(3, DBG_IMPORTANT, "Processing Configuration File: " << file_name << " (depth " << depth << ")");
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

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    SetConfigFilename(file_name, bool(is_pipe));

    memset(config_input_line, '\0', BUFSIZ);

    config_lineno = 0;

    Vector<bool> if_states;
    while (fgets(config_input_line, BUFSIZ, fp)) {
        ++config_lineno;

        if ((token = strchr(config_input_line, '\n')))
            *token = '\0';

        if ((token = strchr(config_input_line, '\r')))
            *token = '\0';

        // strip any prefix whitespace off the line.
        const char *p = skip_ws(config_input_line);
        if (config_input_line != p)
            memmove(config_input_line, p, strlen(p)+1);

        if (strncmp(config_input_line, "#line ", 6) == 0) {
            static char new_file_name[1024];
            static char *file;
            static char new_lineno;
            token = config_input_line + 6;
            new_lineno = strtol(token, &file, 0) - 1;

            if (file == token)
                continue;	/* Not a valid #line directive, may be a comment */

            while (*file && xisspace((unsigned char) *file))
                ++file;

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

        trim_trailing_ws(tmp_line);
        ProcessMacros(tmp_line, tmp_line_len);
        debugs(3, (opt_parse_cfg_only?1:5), "Processing: " << tmp_line);

        if (const char* expr = FindStatement(tmp_line, "if")) {
            if_states.push_back(EvalBoolExpr(expr)); // store last if-statement meaning
        } else if (FindStatement(tmp_line, "endif")) {
            if (!if_states.empty())
                if_states.pop_back(); // remove last if-statement meaning
            else
                fatalf("'endif' without 'if'\n");
        } else if (FindStatement(tmp_line, "else")) {
            if (!if_states.empty())
                if_states.back() = !if_states.back();
            else
                fatalf("'else' without 'if'\n");
        } else if (if_states.empty() || if_states.back()) { // test last if-statement meaning if present
            /* Handle includes here */
            if (tmp_line_len >= 9 && strncmp(tmp_line, "include", 7) == 0 && xisspace(tmp_line[7])) {
                err_count += parseManyConfigFiles(tmp_line + 8, depth + 1);
            } else if (!parse_line(tmp_line)) {
                debugs(3, DBG_CRITICAL, HERE << cfg_filename << ":" << config_lineno << " unrecognized: '" << tmp_line << "'");
                ++err_count;
            }
        }

        safe_free(tmp_line);
        tmp_line_len = 0;

    }
    if (!if_states.empty())
        fatalf("if-statement without 'endif'\n");

    if (is_pipe) {
        int ret = pclose(fp);

        if (ret != 0)
            fatalf("parseConfigFile: '%s' failed with exit code %d\n", file_name, ret);
    } else {
        fclose(fp);
    }

    cfg_filename = orig_cfg_filename;
    config_lineno = orig_config_lineno;

    xfree(tmp_line);
    return err_count;
}

int
parseConfigFile(const char *file_name)
{
    int err_count = 0;

    debugs(5, 4, HERE);

    configFreeMemory();

    ACLMethodData::ThePurgeCount = 0;
    default_all();

    err_count = parseOneConfigFile(file_name, 0);

    defaults_if_none();

    defaults_postscriptum();

    /*
     * We must call configDoConfigure() before leave_suid() because
     * configDoConfigure() is where we turn username strings into
     * uid values.
     */
    configDoConfigure();

    if (!Config.chroot_dir) {
        leave_suid();
        setUmask(Config.umask);
        _db_init(Debug::cache_log, Debug::debugOptions);
        enter_suid();
    }

    if (opt_send_signal == -1) {
        Mgr::RegisterAction("config",
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

    Config.cacheSwap.n_strands = 0; // no diskers by default
    if (Config.cacheSwap.swapDirs == NULL) {
        /* Memory-only cache probably in effect. */
        /* turn off the cache rebuild delays... */
        StoreController::store_dirs_rebuilding = 0;
    } else if (InDaemonMode()) { // no diskers in non-daemon mode
        for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
            const RefCount<SwapDir> sd = Config.cacheSwap.swapDirs[i];
            if (sd->needsDiskStrand())
                sd->disker = Config.workers + (++Config.cacheSwap.n_strands);
        }
    }

    if (Debug::rotateNumber < 0) {
        Debug::rotateNumber = Config.Log.rotateNumber;
    }

#if SIZEOF_OFF_T <= 4
    if (Config.Store.maxObjectSize > 0x7FFF0000) {
        debugs(3, DBG_CRITICAL, "WARNING: This Squid binary can not handle files larger than 2GB. Limiting maximum_object_size to just below 2GB");
        Config.Store.maxObjectSize = 0x7FFF0000;
    }
#endif
    if (0 == Store::Root().maxSize())
        /* people might want a zero-sized cache on purpose */
        (void) 0;
    else if (Store::Root().maxSize() < Config.memMaxSize)
        /* This is bogus. folk with NULL caches will want this */
        debugs(3, DBG_CRITICAL, "WARNING cache_mem is larger than total disk cache space!");

    if (Config.Announce.period > 0) {
        Config.onoff.announce = 1;
    } else if (Config.Announce.period < 1) {
        Config.Announce.period = 86400 * 365;	/* one year */
        Config.onoff.announce = 0;
    }

    if (Config.onoff.httpd_suppress_version_string)
        visible_appname_string = (char *)appname_string;
    else
        visible_appname_string = (char const *)APP_FULLNAME;

#if USE_DNSHELPER
    if (Config.dnsChildren.n_max < 1)
        fatal("No DNS helpers allocated");
#endif

    if (Config.Program.redirect) {
        if (Config.redirectChildren.n_max < 1) {
            Config.redirectChildren.n_max = 0;
            wordlistDestroy(&Config.Program.redirect);
        }
    }

    if (Config.appendDomain)
        if (*Config.appendDomain != '.')
            fatal("append_domain must begin with a '.'");

    if (Config.errHtmlText == NULL)
        Config.errHtmlText = xstrdup(null_string);

#if !HAVE_SETRLIMIT || !defined(RLIMIT_NOFILE)
    if (Config.max_filedescriptors > 0) {
        debugs(0, DBG_IMPORTANT, "WARNING: max_filedescriptors disabled. Operating System setrlimit(RLIMIT_NOFILE) is missing.");
    }
#elif USE_SELECT || USE_SELECT_WIN32
    if (Config.max_filedescriptors > FD_SETSIZE) {
        debugs(0, DBG_IMPORTANT, "WARNING: max_filedescriptors limited to " << FD_SETSIZE << " by select() algorithm.");
    }
#endif

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

    /* Use visible_hostname as default surrogate_id */
    if (!Config.Accel.surrogate_id) {
        const char *t = getMyHostname();
        Config.Accel.surrogate_id = xstrdup( (t?t:"unset-id") );
    }

    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
        Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;

    if (Config.appendDomain)
        Config.appendDomainLen = strlen(Config.appendDomain);
    else
        Config.appendDomainLen = 0;

    if (Config.connect_retries > 10) {
        debugs(0,DBG_CRITICAL, "WARNING: connect_retries cannot be larger than 10. Resetting to 10.");
        Config.connect_retries = 10;
    }

    requirePathnameExists("MIME Config Table", Config.mimeTablePathname);
#if USE_DNSHELPER
    requirePathnameExists("cache_dns_program", Config.Program.dnsserver);
#endif
#if USE_UNLINKD

    requirePathnameExists("unlinkd_program", Config.Program.unlinkd);
#endif
    requirePathnameExists("logfile_daemon", Log::TheConfig.logfile_daemon);
    if (Config.Program.redirect)
        requirePathnameExists("redirect_program", Config.Program.redirect->key);

    requirePathnameExists("Icon Directory", Config.icons.directory);

    if (Config.errorDirectory)
        requirePathnameExists("Error Directory", Config.errorDirectory);

#if USE_HTTP_VIOLATIONS

    {
        const RefreshPattern *R;

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.override_expire)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'override-expire' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.override_lastmod)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'override-lastmod' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.reload_into_ims)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'reload-into-ims' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.ignore_reload)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-reload' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.ignore_no_store)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-no-store' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.ignore_must_revalidate)
                continue;
            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-must-revalidate' in 'refresh_pattern' violates HTTP");
            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.ignore_private)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-private' in 'refresh_pattern' violates HTTP");

            break;
        }

        for (R = Config.Refresh; R; R = R->next) {
            if (!R->flags.ignore_auth)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-auth' in 'refresh_pattern' violates HTTP");

            break;
        }

    }
#endif
#if !USE_HTTP_VIOLATIONS
    Config.onoff.via = 1;
#else

    if (!Config.onoff.via)
        debugs(22, DBG_IMPORTANT, "WARNING: HTTP requires the use of Via");

#endif

    // we enable runtime PURGE checks if there is at least one PURGE method ACL
    // TODO: replace with a dedicated "purge" ACL option?
    Config2.onoff.enable_purge = (ACLMethodData::ThePurgeCount > 0);

    Config2.onoff.mangle_request_headers = (Config.request_header_access != NULL);

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

    debugs(3, DBG_IMPORTANT, "Initializing https proxy context");

    Config.ssl_client.sslContext = sslCreateClientContext(Config.ssl_client.cert, Config.ssl_client.key, Config.ssl_client.version, Config.ssl_client.cipher, Config.ssl_client.options, Config.ssl_client.flags, Config.ssl_client.cafile, Config.ssl_client.capath, Config.ssl_client.crlfile);

    for (CachePeer *p = Config.peers; p != NULL; p = p->next) {
        if (p->use_ssl) {
            debugs(3, DBG_IMPORTANT, "Initializing cache_peer " << p->name << " SSL context");
            p->sslContext = sslCreateClientContext(p->sslcert, p->sslkey, p->sslversion, p->sslcipher, p->ssloptions, p->sslflags, p->sslcafile, p->sslcapath, p->sslcrlfile);
        }
    }

    for (AnyP::PortCfg *s = Config.Sockaddr.http; s != NULL; s = s->next) {
        if (!s->sslBump)
            continue;

        debugs(3, DBG_IMPORTANT, "Initializing http_port " << s->s << " SSL context");
        s->configureSslServerContext();
    }

    for (AnyP::PortCfg *s = Config.Sockaddr.https; s != NULL; s = s->next) {
        debugs(3, DBG_IMPORTANT, "Initializing https_port " << s->s << " SSL context");
        s->configureSslServerContext();
    }

#endif

    // prevent infinite fetch loops in the request parser
    // due to buffer full but not enough data recived to finish parse
    if (Config.maxRequestBufferSize <= Config.maxRequestHeaderSize) {
        fatalf("Client request buffer of %u bytes cannot hold a request with %u bytes of headers." \
               " Change client_request_buffer_max or request_header_max_size limits.",
               (uint32_t)Config.maxRequestBufferSize, (uint32_t)Config.maxRequestHeaderSize);
    }

#if USE_AUTH
    /*
     * disable client side request pipelining. There is a race with
     * Negotiate and NTLM when the client sends a second request on an
     * connection before the authenticate challenge is sent. With
     * pipelining OFF, the client may fail to authenticate, but squid's
     * state will be preserved.
     */
    if (Config.onoff.pipeline_prefetch) {
        Auth::Config *nego = Auth::Config::Find("Negotiate");
        Auth::Config *ntlm = Auth::Config::Find("NTLM");
        if ((nego && nego->active()) || (ntlm && ntlm->active())) {
            debugs(3, DBG_IMPORTANT, "WARNING: pipeline_prefetch breaks NTLM and Negotiate authentication. Forced OFF.");
            Config.onoff.pipeline_prefetch = 0;
        }
    }
#endif
}

/** Parse a line containing an obsolete directive.
 * To upgrade it where possible instead of just "Bungled config" for
 * directives which cannot be marked as simply aliases of the some name.
 * For example if the parameter order and content has changed.
 * Or if the directive has been completely removed.
 */
void
parse_obsolete(const char *name)
{
    // Directives which have been radically changed rather than removed
    if (!strcmp(name, "url_rewrite_concurrency")) {
        int cval;
        parse_int(&cval);
        debugs(3, DBG_CRITICAL, "WARNING: url_rewrite_concurrency upgrade overriding url_rewrite_children settings.");
        Config.redirectChildren.concurrency = cval;
    }
}

/* Parse a time specification from the config file.  Store the
 * result in 'tptr', after converting it to 'units' */
static void
parseTimeLine(time_msec_t * tptr, const char *units,  bool allowMsec)
{
    char *token;
    double d;
    time_msec_t m;
    time_msec_t u;

    if ((u = parseTimeUnits(units, allowMsec)) == 0)
        self_destruct();

    if ((token = strtok(NULL, w_space)) == NULL)
        self_destruct();

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debugs(3, DBG_CRITICAL, "WARNING: No units on '" <<
               config_input_line << "', assuming " <<
               d << " " << units  );
    else if ((m = parseTimeUnits(token, allowMsec)) == 0)
        self_destruct();

    *tptr = static_cast<time_msec_t>(m * d);

    if (static_cast<double>(*tptr) * 2 != m * d * 2) {
        debugs(3, DBG_CRITICAL, "ERROR: Invalid value '" <<
               d << " " << token << ": integer overflow (time_msec_t).");
        self_destruct();
    }
}

static uint64_t
parseTimeUnits(const char *unit, bool allowMsec)
{
    if (allowMsec && !strncasecmp(unit, T_MILLISECOND_STR, strlen(T_MILLISECOND_STR)))
        return 1;

    if (!strncasecmp(unit, T_SECOND_STR, strlen(T_SECOND_STR)))
        return 1000;

    if (!strncasecmp(unit, T_MINUTE_STR, strlen(T_MINUTE_STR)))
        return 60 * 1000;

    if (!strncasecmp(unit, T_HOUR_STR, strlen(T_HOUR_STR)))
        return 3600 * 1000;

    if (!strncasecmp(unit, T_DAY_STR, strlen(T_DAY_STR)))
        return 86400 * 1000;

    if (!strncasecmp(unit, T_WEEK_STR, strlen(T_WEEK_STR)))
        return 86400 * 7 * 1000;

    if (!strncasecmp(unit, T_FORTNIGHT_STR, strlen(T_FORTNIGHT_STR)))
        return 86400 * 14 * 1000;

    if (!strncasecmp(unit, T_MONTH_STR, strlen(T_MONTH_STR)))
        return static_cast<uint64_t>(86400) * 30 * 1000;

    if (!strncasecmp(unit, T_YEAR_STR, strlen(T_YEAR_STR)))
        return static_cast<uint64_t>(86400 * 1000 * 365.2522);

    if (!strncasecmp(unit, T_DECADE_STR, strlen(T_DECADE_STR)))
        return static_cast<uint64_t>(86400 * 1000 * 365.2522 * 10);

    debugs(3, DBG_IMPORTANT, "parseTimeUnits: unknown time unit '" << unit << "'");

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
        debugs(3, DBG_CRITICAL, "WARNING: No units on '" <<
               config_input_line << "', assuming " <<
               d << " " <<  units  );
    else if ((m = parseBytesUnits(token)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<int64_t>(m * d / u);

    if (static_cast<double>(*bptr) * 2 != (m * d / u) * 2) {
        debugs(3, DBG_CRITICAL, "ERROR: Invalid value '" <<
               d << " " << token << ": integer overflow (int64_t).");
        self_destruct();
    }
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
        debugs(3, DBG_CRITICAL, "WARNING: No units on '" <<
               config_input_line << "', assuming " <<
               d << " " <<  units  );
    else if ((m = parseBytesUnits(token)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<size_t>(m * d / u);

    if (static_cast<double>(*bptr) * 2 != (m * d / u) * 2) {
        debugs(3, DBG_CRITICAL, "ERROR: Invalid value '" <<
               d << " " << token << ": integer overflow (size_t).");
        self_destruct();
    }
}

#if !USE_DNSHELPER
static void
parseBytesLineSigned(ssize_t * bptr, const char *units)
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

    if (strcmp(token, "none") == 0 || token[0] == '-' /* -N */) {
        *bptr = -1;
        return;
    }

    d = xatof(token);

    m = u;			/* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
        debugs(3, DBG_CRITICAL, "WARNING: No units on '" <<
               config_input_line << "', assuming " <<
               d << " " <<  units  );
    else if ((m = parseBytesUnits(token)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<ssize_t>(m * d / u);

    if (static_cast<double>(*bptr) * 2 != (m * d / u) * 2) {
        debugs(3, DBG_CRITICAL, "ERROR: Invalid value '" <<
               d << " " << token << ": integer overflow (ssize_t).");
        self_destruct();
    }
}
#endif

#if USE_SSL
/**
 * Parse bytes from a string.
 * Similar to the parseBytesLine function but parses the string value instead of
 * the current token value.
 */
static void parseBytesOptionValue(size_t * bptr, const char *units, char const * value)
{
    int u;
    if ((u = parseBytesUnits(units)) == 0) {
        self_destruct();
        return;
    }

    // Find number from string beginning.
    char const * number_begin = value;
    char const * number_end = value;

    while ((*number_end >= '0' && *number_end <= '9')) {
        ++number_end;
    }

    String number;
    number.limitInit(number_begin, number_end - number_begin);

    int d = xatoi(number.termedBuf());
    int m;
    if ((m = parseBytesUnits(number_end)) == 0) {
        self_destruct();
        return;
    }

    *bptr = static_cast<size_t>(m * d / u);
    if (static_cast<double>(*bptr) * 2 != (m * d / u) * 2)
        self_destruct();
}
#endif

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

    debugs(3, DBG_CRITICAL, "WARNING: Unknown bytes unit '" << unit << "'");

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

void
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
dump_address(StoreEntry * entry, const char *name, Ip::Address &addr)
{
    char buf[MAX_IPSTRLEN];
    storeAppendPrintf(entry, "%s %s\n", name, addr.NtoA(buf,MAX_IPSTRLEN) );
}

static void
parse_address(Ip::Address *addr)
{
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token,"any_addr"))
        addr->SetAnyAddr();
    else if ( (!strcmp(token,"no_addr")) || (!strcmp(token,"full_mask")) )
        addr->SetNoAddr();
    else if ( (*addr = token) ) // try parse numeric/IPA
        (void) 0;
    else
        addr->GetHostByName(token); // dont use ipcache
}

static void
free_address(Ip::Address *addr)
{
    addr->SetEmpty();
}

CBDATA_TYPE(AclAddress);

static void
dump_acl_address(StoreEntry * entry, const char *name, AclAddress * head)
{
    char buf[MAX_IPSTRLEN];
    AclAddress *l;

    for (l = head; l; l = l->next) {
        if (!l->addr.IsAnyAddr())
            storeAppendPrintf(entry, "%s %s", name, l->addr.NtoA(buf,MAX_IPSTRLEN));
        else
            storeAppendPrintf(entry, "%s autoselect", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
freed_acl_address(void *data)
{
    AclAddress *l = static_cast<AclAddress *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_address(AclAddress ** head)
{
    AclAddress *l;
    AclAddress **tail = head;	/* sane name below */
    CBDATA_INIT_TYPE_FREECB(AclAddress, freed_acl_address);
    l = cbdataAlloc(AclAddress);
    parse_address(&l->addr);
    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_address(AclAddress ** head)
{
    while (*head) {
        AclAddress *l = *head;
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
    unsigned int tos;           /* Initially uint for strtoui. Casted to tos_t before return */
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    if (!xstrtoui(token, NULL, &tos, 0, std::numeric_limits<tos_t>::max())) {
        self_destruct();
        return;
    }

    CBDATA_INIT_TYPE_FREECB(acl_tos, freed_acl_tos);

    l = cbdataAlloc(acl_tos);

    l->tos = (tos_t)tos;

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

#if SO_MARK && USE_LIBCAP

CBDATA_TYPE(acl_nfmark);

static void
dump_acl_nfmark(StoreEntry * entry, const char *name, acl_nfmark * head)
{
    acl_nfmark *l;

    for (l = head; l; l = l->next) {
        if (l->nfmark > 0)
            storeAppendPrintf(entry, "%s 0x%02X", name, l->nfmark);
        else
            storeAppendPrintf(entry, "%s none", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
freed_acl_nfmark(void *data)
{
    acl_nfmark *l = static_cast<acl_nfmark *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_nfmark(acl_nfmark ** head)
{
    acl_nfmark *l;
    acl_nfmark **tail = head;	/* sane name below */
    nfmark_t mark;
    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    if (!xstrtoui(token, NULL, &mark, 0, std::numeric_limits<nfmark_t>::max())) {
        self_destruct();
        return;
    }

    CBDATA_INIT_TYPE_FREECB(acl_nfmark, freed_acl_nfmark);

    l = cbdataAlloc(acl_nfmark);

    l->nfmark = mark;

    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_nfmark(acl_nfmark ** head)
{
    while (*head) {
        acl_nfmark *l = *head;
        *head = l->next;
        l->next = NULL;
        cbdataFree(l);
    }
}
#endif /* SO_MARK */

CBDATA_TYPE(AclSizeLimit);

static void
dump_acl_b_size_t(StoreEntry * entry, const char *name, AclSizeLimit * head)
{
    AclSizeLimit *l;

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
    AclSizeLimit *l = static_cast<AclSizeLimit *>(data);
    aclDestroyAclList(&l->aclList);
}

static void
parse_acl_b_size_t(AclSizeLimit ** head)
{
    AclSizeLimit *l;
    AclSizeLimit **tail = head;	/* sane name below */

    CBDATA_INIT_TYPE_FREECB(AclSizeLimit, freed_acl_b_size_t);

    l = cbdataAlloc(AclSizeLimit);

    parse_b_int64_t(&l->size);

    aclParseAclList(LegacyParser, &l->aclList);

    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_b_size_t(AclSizeLimit ** head)
{
    while (*head) {
        AclSizeLimit *l = *head;
        *head = l->next;
        l->next = NULL;
        cbdataFree(l);
    }
}

#if USE_DELAY_POOLS

#include "DelayPools.h"
#include "DelayConfig.h"
/* do nothing - free_delay_pool_count is the magic free function.
 * this is why delay_pool_count isn't just marked TYPE: u_short
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

#if USE_DELAY_POOLS
#include "ClientDelayConfig.h"
/* do nothing - free_client_delay_pool_count is the magic free function.
 * this is why client_delay_pool_count isn't just marked TYPE: u_short
 */

#define free_client_delay_pool_access(X)
#define free_client_delay_pool_rates(X)
#define dump_client_delay_pool_access(X, Y, Z)
#define dump_client_delay_pool_rates(X, Y, Z)

static void
free_client_delay_pool_count(ClientDelayConfig * cfg)
{
    cfg->freePoolCount();
}

static void
dump_client_delay_pool_count(StoreEntry * entry, const char *name, ClientDelayConfig &cfg)
{
    cfg.dumpPoolCount (entry, name);
}

static void
parse_client_delay_pool_count(ClientDelayConfig * cfg)
{
    cfg->parsePoolCount();
}

static void
parse_client_delay_pool_rates(ClientDelayConfig * cfg)
{
    cfg->parsePoolRates();
}

static void
parse_client_delay_pool_access(ClientDelayConfig * cfg)
{
    cfg->parsePoolAccess(LegacyParser);
}
#endif

#if USE_HTTP_VIOLATIONS
static void
dump_http_header_access(StoreEntry * entry, const char *name, const HeaderManglers *manglers)
{
    if (manglers)
        manglers->dumpAccess(entry, name);
}

static void
parse_http_header_access(HeaderManglers **pm)
{
    char *t = NULL;

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(3, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, DBG_CRITICAL, "parse_http_header_access: missing header name.");
        return;
    }

    if (!*pm)
        *pm = new HeaderManglers;
    HeaderManglers *manglers = *pm;
    headerMangler *mangler = manglers->track(t);
    assert(mangler);
    parse_acl_access(&mangler->access_list);
}

static void
free_HeaderManglers(HeaderManglers **pm)
{
    // we delete the entire http_header_* mangler configuration at once
    if (const HeaderManglers *manglers = *pm) {
        delete manglers;
        *pm = NULL;
    }
}

static void
dump_http_header_replace(StoreEntry * entry, const char *name, const HeaderManglers *manglers)
{
    if (manglers)
        manglers->dumpReplacement(entry, name);
}

static void
parse_http_header_replace(HeaderManglers **pm)
{
    char *t = NULL;

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(3, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, DBG_CRITICAL, "parse_http_header_replace: missing header name.");
        return;
    }

    const char *value = t + strlen(t) + 1;

    if (!*pm)
        *pm = new HeaderManglers;
    HeaderManglers *manglers = *pm;
    manglers->setReplacement(t, value);
}

#endif

static void
dump_cachedir(StoreEntry * entry, const char *name, SquidConfig::_cacheSwap swap)
{
    SwapDir *s;
    int i;
    assert (entry);

    for (i = 0; i < swap.n_configured; ++i) {
        s = dynamic_cast<SwapDir *>(swap.swapDirs[i].getRaw());
        if (!s) continue;
        storeAppendPrintf(entry, "%s %s %s", name, s->type(), s->path);
        s->dump(*entry);
        storeAppendPrintf(entry, "\n");
    }
}

static int
check_null_string(char *s)
{
    return s == NULL;
}

#if USE_AUTH
static void
parse_authparam(Auth::ConfigVector * config)
{
    char *type_str;
    char *param_str;

    if ((type_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((param_str = strtok(NULL, w_space)) == NULL)
        self_destruct();

    /* find a configuration for the scheme in the currently parsed configs... */
    Auth::Config *schemeCfg = Auth::Config::Find(type_str);

    if (schemeCfg == NULL) {
        /* Create a configuration based on the scheme info */
        Auth::Scheme::Pointer theScheme = Auth::Scheme::Find(type_str);

        if (theScheme == NULL) {
            debugs(3, DBG_CRITICAL, "Parsing Config File: Unknown authentication scheme '" << type_str << "'.");
            self_destruct();
        }

        config->push_back(theScheme->createConfig());
        schemeCfg = Auth::Config::Find(type_str);
        if (schemeCfg == NULL) {
            debugs(3, DBG_CRITICAL, "Parsing Config File: Corruption configuring authentication scheme '" << type_str << "'.");
            self_destruct();
        }
    }

    schemeCfg->parse(schemeCfg, config->size(), param_str);
}

static void
free_authparam(Auth::ConfigVector * cfg)
{
    /* Wipe the Auth globals and Detach/Destruct component config + state. */
    cfg->clean();

    /* remove our pointers to the probably-dead sub-configs */
    while (cfg->size()) {
        cfg->pop_back();
    }

    /* on reconfigure initialize new auth schemes for the new config. */
    if (reconfiguring) {
        Auth::Init();
    }
}

static void
dump_authparam(StoreEntry * entry, const char *name, Auth::ConfigVector cfg)
{
    for (Auth::ConfigVector::iterator  i = cfg.begin(); i != cfg.end(); ++i)
        (*i)->dump(entry, name, (*i));
}
#endif /* USE_AUTH */

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
parse_cachedir(SquidConfig::_cacheSwap * swap)
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

    for (i = 0; i < swap->n_configured; ++i) {
        assert (swap->swapDirs[i].getRaw());

        if ((strcasecmp(path_str, dynamic_cast<SwapDir *>(swap->swapDirs[i].getRaw())->path)) == 0) {
            /* this is specific to on-fs Stores. The right
             * way to handle this is probably to have a mapping
             * from paths to stores, and have on-fs stores
             * register with that, and lookip in that in their
             * own setup logic. RBC 20041225. TODO.
             */

            sd = dynamic_cast<SwapDir *>(swap->swapDirs[i].getRaw());

            if (strcmp(sd->type(), StoreFileSystem::FileSystems().items[fs]->type()) != 0) {
                debugs(3, DBG_CRITICAL, "ERROR: Can't change type of existing cache_dir " <<
                       sd->type() << " " << sd->path << " to " << type_str << ". Restart required");
                return;
            }

            sd->reconfigure();

            update_maxobjsize();

            return;
        }
    }

    /* new cache_dir */
    if (swap->n_configured > 63) {
        /* 7 bits, signed */
        debugs(3, DBG_CRITICAL, "WARNING: There is a fixed maximum of 63 cache_dir entries Squid can handle.");
        debugs(3, DBG_CRITICAL, "WARNING: '" << path_str << "' is one to many.");
        self_destruct();
        return;
    }

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
dump_peer(StoreEntry * entry, const char *name, CachePeer * p)
{
    CachePeerDomainList *d;
    NeighborTypeDomainList *t;
    LOCAL_ARRAY(char, xname, 128);

    while (p != NULL) {
        storeAppendPrintf(entry, "%s %s %s %d %d name=%s",
                          name,
                          p->host,
                          neighborTypeStr(p),
                          p->http_port,
                          p->icp.port,
                          p->name);
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
 * utility function to prevent getservbyname() being called with a numeric value
 * on Windows at least it returns garage results.
 */
static bool
isUnsignedNumeric(const char *str, size_t len)
{
    if (len < 1) return false;

    for (; len >0 && *str; ++str, --len) {
        if (! isdigit(*str))
            return false;
    }
    return true;
}

/**
 \param proto	'tcp' or 'udp' for protocol
 \returns       Port the named service is supposed to be listening on.
 */
static unsigned short
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
    if ( !isUnsignedNumeric(token, strlen(token)) )
        port = getservbyname(token, proto);
    if (port != NULL) {
        return ntohs((unsigned short)port->s_port);
    }
    /** Or a numeric translation of the config text. */
    return xatos(token);
}

/**
 \returns       Port the named TCP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline unsigned short
GetTcpService(void)
{
    return GetService("tcp");
}

/**
 \returns       Port the named UDP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline unsigned short
GetUdpService(void)
{
    return GetService("udp");
}

static void
parse_peer(CachePeer ** head)
{
    char *token = NULL;
    CachePeer *p;
    CBDATA_INIT_TYPE_FREECB(CachePeer, peerDestroy);
    p = cbdataAlloc(CachePeer);
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
    p->connection_auth = 2;    /* auto */

    while ((token = strtok(NULL, w_space))) {
        if (!strcasecmp(token, "proxy-only")) {
            p->options.proxy_only = 1;
        } else if (!strcasecmp(token, "no-query")) {
            p->options.no_query = 1;
        } else if (!strcasecmp(token, "background-ping")) {
            p->options.background_ping = 1;
        } else if (!strcasecmp(token, "no-digest")) {
            p->options.no_digest = 1;
        } else if (!strcasecmp(token, "no-tproxy")) {
            p->options.no_tproxy = 1;
        } else if (!strcasecmp(token, "multicast-responder")) {
            p->options.mcast_responder = 1;
#if PEER_MULTICAST_SIBLINGS
        } else if (!strcasecmp(token, "multicast-siblings")) {
            p->options.mcast_siblings = 1;
#endif
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
        } else if (!strncasecmp(token, "htcp=", 5) || !strncasecmp(token, "htcp-", 5)) {
            /* Note: The htcp- form is deprecated, replaced by htcp= */
            p->options.htcp = 1;
            char *tmp = xstrdup(token+5);
            char *mode, *nextmode;
            for (mode = nextmode = tmp; mode; mode = nextmode) {
                nextmode = strchr(mode, ',');
                if (nextmode) {
                    *nextmode = '\0';
                    ++nextmode;
                }
                if (!strcasecmp(mode, "no-clr")) {
                    if (p->options.htcp_only_clr)
                        fatalf("parse_peer: can't set htcp-no-clr and htcp-only-clr simultaneously");
                    p->options.htcp_no_clr = 1;
                } else if (!strcasecmp(mode, "no-purge-clr")) {
                    p->options.htcp_no_purge_clr = 1;
                } else if (!strcasecmp(mode, "only-clr")) {
                    if (p->options.htcp_no_clr)
                        fatalf("parse_peer: can't set htcp no-clr and only-clr simultaneously");
                    p->options.htcp_only_clr = 1;
                } else if (!strcasecmp(mode, "forward-clr")) {
                    p->options.htcp_forward_clr = 1;
                } else if (!strcasecmp(mode, "oldsquid")) {
                    p->options.htcp_oldsquid = 1;
                } else {
                    fatalf("invalid HTCP mode '%s'", mode);
                }
            }
            safe_free(tmp);
#endif
        } else if (!strcasecmp(token, "no-netdb-exchange")) {
            p->options.no_netdb_exchange = 1;

        } else if (!strcasecmp(token, "carp")) {
            if (p->type != PEER_PARENT)
                fatalf("parse_peer: non-parent carp peer %s/%d\n", p->host, p->http_port);

            p->options.carp = 1;
        } else if (!strncasecmp(token, "carp-key=", 9)) {
            if (p->options.carp != 1)
                fatalf("parse_peer: carp-key specified on non-carp peer %s/%d\n", p->host, p->http_port);
            p->options.carp_key.set=1;
            char *nextkey=token+strlen("carp-key="), *key=nextkey;
            for (; key; key = nextkey) {
                nextkey=strchr(key,',');
                if (nextkey) ++nextkey; // skip the comma, any
                if (0==strncasecmp(key,"scheme",6)) {
                    p->options.carp_key.scheme=1;
                } else if (0==strncasecmp(key,"host",4)) {
                    p->options.carp_key.host=1;
                } else if (0==strncasecmp(key,"port",4)) {
                    p->options.carp_key.port=1;
                } else if (0==strncasecmp(key,"path",4)) {
                    p->options.carp_key.path=1;
                } else if (0==strncasecmp(key,"params",6)) {
                    p->options.carp_key.params=1;
                } else {
                    fatalf("invalid carp-key '%s'",key);
                }
            }
        } else if (!strcasecmp(token, "userhash")) {
#if USE_AUTH
            if (p->type != PEER_PARENT)
                fatalf("parse_peer: non-parent userhash peer %s/%d\n", p->host, p->http_port);

            p->options.userhash = 1;
#else
            fatalf("parse_peer: userhash requires authentication. peer %s/%d\n", p->host, p->http_port);
#endif
        } else if (!strcasecmp(token, "sourcehash")) {
            if (p->type != PEER_PARENT)
                fatalf("parse_peer: non-parent sourcehash peer %s/%d\n", p->host, p->http_port);

            p->options.sourcehash = 1;

        } else if (!strcasecmp(token, "no-delay")) {
#if USE_DELAY_POOLS
            p->options.no_delay = 1;
#else
            debugs(0, DBG_CRITICAL, "WARNING: cache_peer option 'no-delay' requires --enable-delay-pools");
#endif
        } else if (!strncasecmp(token, "login=", 6)) {
            p->login = xstrdup(token + 6);
            rfc1738_unescape(p->login);
        } else if (!strncasecmp(token, "connect-timeout=", 16)) {
            p->connect_timeout = xatoi(token + 16);
        } else if (!strncasecmp(token, "connect-fail-limit=", 19)) {
            p->connect_fail_limit = xatoi(token + 19);
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
            p->sslversion = xatoi(token + 11);
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
            p->sslcrlfile = xstrdup(token + 11);
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
        } else if (strcmp(token, "connection-auth=off") == 0) {
            p->connection_auth = 0;
        } else if (strcmp(token, "connection-auth") == 0) {
            p->connection_auth = 1;
        } else if (strcmp(token, "connection-auth=on") == 0) {
            p->connection_auth = 1;
        } else if (strcmp(token, "connection-auth=auto") == 0) {
            p->connection_auth = 2;
        } else {
            debugs(3, DBG_CRITICAL, "parse_peer: token='" << token << "'");
            self_destruct();
        }
    }

    if (peerFindByName(p->name))
        fatalf("ERROR: cache_peer %s specified twice\n", p->name);

    if (p->weight < 1)
        p->weight = 1;

    if (p->connect_fail_limit < 1)
        p->connect_fail_limit = 10;

    p->icp.version = ICP_VERSION_CURRENT;

    p->testing_now = false;

#if USE_CACHE_DIGESTS

    if (!p->options.no_digest) {
        /* XXX This looks odd.. who has the original pointer
         * then?
         */
        PeerDigest *pd = peerDigestCreate(p);
        p->digest = cbdataReference(pd);
    }

#endif

    p->index =  ++Config.npeers;

    while (*head != NULL)
        head = &(*head)->next;

    *head = p;

    peerClearRRStart();
}

static void
free_peer(CachePeer ** P)
{
    CachePeer *p;

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
dump_cachemgrpasswd(StoreEntry * entry, const char *name, Mgr::ActionPasswordList * list)
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
parse_cachemgrpasswd(Mgr::ActionPasswordList ** head)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    Mgr::ActionPasswordList *p;
    Mgr::ActionPasswordList **P;
    parse_string(&passwd);
    parse_wordlist(&actions);
    p = new Mgr::ActionPasswordList;
    p->passwd = passwd;
    p->actions = actions;

    for (P = head; *P; P = &(*P)->next) {
        /*
         * See if any of the actions from this line already have a
         * password from previous lines.  The password checking
         * routines in cache_manager.c take the the password from
         * the first Mgr::ActionPasswordList that contains the
         * requested action.  Thus, we should warn users who might
         * think they can have two passwords for the same action.
         */
        wordlist *w;
        wordlist *u;

        for (w = (*P)->actions; w; w = w->next) {
            for (u = actions; u; u = u->next) {
                if (strcmp(w->key, u->key))
                    continue;

                debugs(0, DBG_CRITICAL, "WARNING: action '" << u->key << "' (line " << config_lineno << ") already has a password");
            }
        }
    }

    *P = p;
}

static void
free_cachemgrpasswd(Mgr::ActionPasswordList ** head)
{
    Mgr::ActionPasswordList *p;

    while ((p = *head) != NULL) {
        *head = p->next;
        xfree(p->passwd);
        wordlistDestroy(&p->actions);
        xfree(p);
    }
}

static void
dump_denyinfo(StoreEntry * entry, const char *name, AclDenyInfoList * var)
{
    AclNameList *a;

    while (var != NULL) {
        storeAppendPrintf(entry, "%s %s", name, var->err_page_name);

        for (a = var->acl_list; a != NULL; a = a->next)
            storeAppendPrintf(entry, " %s", a->name);

        storeAppendPrintf(entry, "\n");

        var = var->next;
    }
}

static void
parse_denyinfo(AclDenyInfoList ** var)
{
    aclParseDenyInfoLine(var);
}

void
free_denyinfo(AclDenyInfoList ** list)
{
    AclDenyInfoList *a = NULL;
    AclDenyInfoList *a_next = NULL;
    AclNameList *l = NULL;
    AclNameList *l_next = NULL;

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
    CachePeer *p;

    if (!(host = strtok(NULL, w_space)))
        self_destruct();

    if ((p = peerFindByName(host)) == NULL) {
        debugs(15, DBG_CRITICAL, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
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
        CachePeerDomainList *l = NULL;
        CachePeerDomainList **L = NULL;
        CachePeer *p;

        if ((p = peerFindByName(host)) == NULL) {
            debugs(15, DBG_CRITICAL, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
            continue;
        }

        l = static_cast<CachePeerDomainList *>(xcalloc(1, sizeof(CachePeerDomainList)));
        l->do_ping = true;

        if (*domain == '!') {	/* check for !.edu */
            l->do_ping = false;
            ++domain;
        }

        l->domain = xstrdup(domain);

        for (L = &(p->peer_domain); *L; L = &((*L)->next));
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
        NeighborTypeDomainList *l = NULL;
        NeighborTypeDomainList **L = NULL;
        CachePeer *p;

        if ((p = peerFindByName(host)) == NULL) {
            debugs(15, DBG_CRITICAL, "" << cfg_filename << ", line " << config_lineno << ": No cache_peer '" << host << "'");
            return;
        }

        l = static_cast<NeighborTypeDomainList *>(xcalloc(1, sizeof(NeighborTypeDomainList)));
        l->type = parseNeighborType(type);
        l->domain = xstrdup(domain);

        for (L = &(p->typelist); *L; L = &((*L)->next));
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

    if (!strcasecmp(token, "on")) {
        *var = 1;
    } else if (!strcasecmp(token, "enable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'enable' is deprecated. Please update to use 'on'.");
        *var = 1;
    } else if (!strcasecmp(token, "off")) {
        *var = 0;
    } else if (!strcasecmp(token, "disable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'disable' is deprecated. Please update to use 'off'.");
        *var = 0;
    } else {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Invalid option: Boolean options can only be 'on' or 'off'.");
        self_destruct();
    }
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

    if (!strcasecmp(token, "on")) {
        *var = 1;
    } else if (!strcasecmp(token, "enable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'enable' is deprecated. Please update to use value 'on'.");
        *var = 1;
    } else if (!strcasecmp(token, "warn")) {
        *var = -1;
    } else if (!strcasecmp(token, "off")) {
        *var = 0;
    } else if (!strcasecmp(token, "disable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'disable' is deprecated. Please update to use value 'off'.");
        *var = 0;
    } else {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Invalid option: Tristate options can only be 'on', 'off', or 'warn'.");
        self_destruct();
    }
}

#define free_tristate free_int

static void
dump_refreshpattern(StoreEntry * entry, const char *name, RefreshPattern * head)
{
    while (head != NULL) {
        storeAppendPrintf(entry, "%s%s %s %d %d%% %d",
                          name,
                          head->flags.icase ? " -i" : null_string,
                          head->pattern,
                          (int) head->min / 60,
                          (int) (100.0 * head->pct + 0.5),
                          (int) head->max / 60);

        if (head->max_stale >= 0)
            storeAppendPrintf(entry, " max-stale=%d", head->max_stale);

        if (head->flags.refresh_ims)
            storeAppendPrintf(entry, " refresh-ims");

        if (head->flags.store_stale)
            storeAppendPrintf(entry, " store-stale");

#if USE_HTTP_VIOLATIONS

        if (head->flags.override_expire)
            storeAppendPrintf(entry, " override-expire");

        if (head->flags.override_lastmod)
            storeAppendPrintf(entry, " override-lastmod");

        if (head->flags.reload_into_ims)
            storeAppendPrintf(entry, " reload-into-ims");

        if (head->flags.ignore_reload)
            storeAppendPrintf(entry, " ignore-reload");

        if (head->flags.ignore_no_store)
            storeAppendPrintf(entry, " ignore-no-store");

        if (head->flags.ignore_must_revalidate)
            storeAppendPrintf(entry, " ignore-must-revalidate");

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
parse_refreshpattern(RefreshPattern ** head)
{
    char *token;
    char *pattern;
    time_t min = 0;
    double pct = 0.0;
    time_t max = 0;
    int refresh_ims = 0;
    int store_stale = 0;
    int max_stale = -1;

#if USE_HTTP_VIOLATIONS

    int override_expire = 0;
    int override_lastmod = 0;
    int reload_into_ims = 0;
    int ignore_reload = 0;
    int ignore_no_store = 0;
    int ignore_must_revalidate = 0;
    int ignore_private = 0;
    int ignore_auth = 0;
#endif

    int i;
    RefreshPattern *t;
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

    /* catch negative and insanely huge values close to 32-bit wrap */
    if (i < 0) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern minimum age negative. Cropped back to zero.");
        i = 0;
    }
    if (i > 60*24*365) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern minimum age too high. Cropped back to 1 year.");
        i = 60*24*365;
    }

    min = (time_t) (i * 60);	/* convert minutes to seconds */

    i = GetPercentage();	/* token: pct */

    pct = (double) i / 100.0;

    i = GetInteger();		/* token: max */

    /* catch negative and insanely huge values close to 32-bit wrap */
    if (i < 0) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern maximum age negative. Cropped back to zero.");
        i = 0;
    }
    if (i > 60*24*365) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern maximum age too high. Cropped back to 1 year.");
        i = 60*24*365;
    }

    max = (time_t) (i * 60);	/* convert minutes to seconds */

    /* Options */
    while ((token = strtok(NULL, w_space)) != NULL) {
        if (!strcmp(token, "refresh-ims")) {
            refresh_ims = 1;
        } else if (!strcmp(token, "store-stale")) {
            store_stale = 1;
        } else if (!strncmp(token, "max-stale=", 10)) {
            max_stale = xatoi(token + 10);
#if USE_HTTP_VIOLATIONS

        } else if (!strcmp(token, "override-expire"))
            override_expire = 1;
        else if (!strcmp(token, "override-lastmod"))
            override_lastmod = 1;
        else if (!strcmp(token, "ignore-no-store"))
            ignore_no_store = 1;
        else if (!strcmp(token, "ignore-must-revalidate"))
            ignore_must_revalidate = 1;
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

        } else if (!strcmp(token, "ignore-no-cache")) {
            debugs(22, DBG_PARSE_NOTE(2), "UPGRADE: refresh_pattern option 'ignore-no-cache' is obsolete. Remove it.");
        } else
            debugs(22, DBG_CRITICAL, "refreshAddToList: Unknown option '" << pattern << "': " << token);
    }

    if ((errcode = regcomp(&comp, pattern, flags)) != 0) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        debugs(22, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(22, DBG_CRITICAL, "refreshAddToList: Invalid regular expression '" << pattern << "': " << errbuf);
        return;
    }

    pct = pct < 0.0 ? 0.0 : pct;
    max = max < 0 ? 0 : max;
    t = static_cast<RefreshPattern *>(xcalloc(1, sizeof(RefreshPattern)));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->min = min;
    t->pct = pct;
    t->max = max;

    if (flags & REG_ICASE)
        t->flags.icase = 1;

    if (refresh_ims)
        t->flags.refresh_ims = 1;

    if (store_stale)
        t->flags.store_stale = 1;

    t->max_stale = max_stale;

#if USE_HTTP_VIOLATIONS

    if (override_expire)
        t->flags.override_expire = 1;

    if (override_lastmod)
        t->flags.override_lastmod = 1;

    if (reload_into_ims)
        t->flags.reload_into_ims = 1;

    if (ignore_reload)
        t->flags.ignore_reload = 1;

    if (ignore_no_store)
        t->flags.ignore_no_store = 1;

    if (ignore_must_revalidate)
        t->flags.ignore_must_revalidate = 1;

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
free_refreshpattern(RefreshPattern ** head)
{
    RefreshPattern *t;

    while ((t = *head) != NULL) {
        *head = t->next;
        safe_free(t->pattern);
        regfree(&t->compiled_pattern);
        safe_free(t);
    }

#if USE_HTTP_VIOLATIONS
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
    if (!var) {
        self_destruct();
        return;
    }

    unsigned char *token = (unsigned char *) strtok(NULL, null_string);
    safe_free(*var);

    if (!token) {
        self_destruct();
        return;
    }

    while (*token && xisspace(*token))
        ++token;

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
    time_msec_t tval;
    parseTimeLine(&tval, T_SECOND_STR, false);
    *var = static_cast<time_t>(tval/1000);
}

static void
free_time_t(time_t * var)
{
    *var = 0;
}

#if !USE_DNSHELPER
static void
dump_time_msec(StoreEntry * entry, const char *name, time_msec_t var)
{
    if (var % 1000)
        storeAppendPrintf(entry, "%s %" PRId64 " milliseconds\n", name, var);
    else
        storeAppendPrintf(entry, "%s %d seconds\n", name, (int)(var/1000) );
}

void
parse_time_msec(time_msec_t * var)
{
    parseTimeLine(var, T_SECOND_STR, true);
}

static void
free_time_msec(time_msec_t * var)
{
    *var = 0;
}
#endif

#if UNUSED_CODE
static void
dump_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d\n", name, (int) var);
}
#endif

static void
dump_b_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}

#if !USE_DNSHELPER
static void
dump_b_ssize_t(StoreEntry * entry, const char *name, ssize_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}
#endif

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
    storeAppendPrintf(entry, "%s %" PRId64 " %s\n", name, var, B_BYTES_STR);
}

static void
dump_kb_int64_t(StoreEntry * entry, const char *name, int64_t var)
{
    storeAppendPrintf(entry, "%s %" PRId64 " %s\n", name, var, B_KBYTES_STR);
}

#if UNUSED_CODE
static void
parse_size_t(size_t * var)
{
    int i;
    i = GetInteger();
    *var = (size_t) i;
}
#endif

static void
parse_b_size_t(size_t * var)
{
    parseBytesLine(var, B_BYTES_STR);
}

#if !USE_DNSHELPER
static void
parse_b_ssize_t(ssize_t * var)
{
    parseBytesLineSigned(var, B_BYTES_STR);
}
#endif

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

#if !USE_DNSHELPER
static void
free_ssize_t(ssize_t * var)
{
    *var = 0;
}
#endif

static void
free_b_int64_t(int64_t * var)
{
    *var = 0;
}

#define free_b_size_t free_size_t
#define free_b_ssize_t free_ssize_t
#define free_kb_size_t free_size_t
#define free_mb_size_t free_size_t
#define free_gb_size_t free_size_t
#define free_kb_int64_t free_b_int64_t

static void
dump_u_short(StoreEntry * entry, const char *name, unsigned short var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

static void
free_u_short(unsigned short * u)
{
    *u = 0;
}

static void
parse_u_short(unsigned short * var)
{
    ConfigParser::ParseUShort(var);
}

void
ConfigParser::ParseUShort(unsigned short *var)
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

#if 0 /* now unused */
static int
check_null_wordlist(wordlist * w)
{
    return w == NULL;
}
#endif

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
    else {
        debugs(0, DBG_PARSE_NOTE(2), "ERROR: Invalid option '" << token << "': 'uri_whitespace' accepts 'strip', 'deny', 'allow', 'encode', and 'chop'.");
        self_destruct();
    }
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

inline void
free_YesNoNone(YesNoNone *)
{
    // do nothing: no explicit cleanup is required
}

static void
parse_YesNoNone(YesNoNone *option)
{
    int value = 0;
    parse_onoff(&value);
    option->configure(value > 0);
}

static void
dump_YesNoNone(StoreEntry * entry, const char *name, YesNoNone &option)
{
    if (option.configured())
        dump_onoff(entry, name, option ? 1 : 0);
}

static void
free_memcachemode(SquidConfig * config)
{
    return;
}

static void
parse_memcachemode(SquidConfig * config)
{
    char *token = strtok(NULL, w_space);
    if (!token)
        self_destruct();

    if (strcmp(token, "always") == 0) {
        Config.onoff.memory_cache_first = 1;
        Config.onoff.memory_cache_disk = 1;
    } else if (strcmp(token, "disk") == 0) {
        Config.onoff.memory_cache_first = 0;
        Config.onoff.memory_cache_disk = 1;
    } else if (strncmp(token, "net", 3) == 0) {
        Config.onoff.memory_cache_first = 1;
        Config.onoff.memory_cache_disk = 0;
    } else if (strcmp(token, "never") == 0) {
        Config.onoff.memory_cache_first = 0;
        Config.onoff.memory_cache_disk = 0;
    } else {
        debugs(0, DBG_PARSE_NOTE(2), "ERROR: Invalid option '" << token << "': 'memory_cache_mode' accepts 'always', 'disk', 'network', and 'never'.");
        self_destruct();
    }
}

static void
dump_memcachemode(StoreEntry * entry, const char *name, SquidConfig &config)
{
    storeAppendPrintf(entry, "%s ", name);
    if (Config.onoff.memory_cache_first && Config.onoff.memory_cache_disk)
        storeAppendPrintf(entry, "always");
    else if (!Config.onoff.memory_cache_first && Config.onoff.memory_cache_disk)
        storeAppendPrintf(entry, "disk");
    else if (Config.onoff.memory_cache_first && !Config.onoff.memory_cache_disk)
        storeAppendPrintf(entry, "network");
    else if (!Config.onoff.memory_cache_first && !Config.onoff.memory_cache_disk)
        storeAppendPrintf(entry, "none");
    storeAppendPrintf(entry, "\n");
}

#include "cf_parser.cci"

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

    debugs(15, DBG_CRITICAL, "WARNING: Unknown neighbor type: " << s);

    return PEER_SIBLING;
}

#if USE_WCCPv2
static void
parse_IpAddress_list(Ip::Address_list ** head)
{
    char *token;
    Ip::Address_list *s;
    Ip::Address ipa;

    while ((token = strtok(NULL, w_space))) {
        if (GetHostWithPort(token, &ipa)) {

            while (*head)
                head = &(*head)->next;

            s = static_cast<Ip::Address_list *>(xcalloc(1, sizeof(*s)));
            s->s = ipa;

            *head = s;
        } else
            self_destruct();
    }
}

static void
dump_IpAddress_list(StoreEntry * e, const char *n, const Ip::Address_list * s)
{
    char ntoabuf[MAX_IPSTRLEN];

    while (s) {
        storeAppendPrintf(e, "%s %s\n",
                          n,
                          s->s.NtoA(ntoabuf,MAX_IPSTRLEN));
        s = s->next;
    }
}

static void
free_IpAddress_list(Ip::Address_list ** head)
{
    if (*head) delete *head;
    *head = NULL;
}

#if CURRENTLY_UNUSED
/* This code was previously used by http_port. Left as it really should
 * be used by icp_port and htcp_port
 */
static int
check_null_IpAddress_list(const Ip::Address_list * s)
{
    return NULL == s;
}

#endif /* CURRENTLY_UNUSED */
#endif /* USE_WCCPv2 */

static void
parsePortSpecification(AnyP::PortCfg * s, char *token)
{
    char *host = NULL;
    unsigned short port = 0;
    char *t = NULL;
    char *junk = NULL;

    s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
    s->name = xstrdup(token);
    s->connection_auth_disabled = false;

    if (*token == '[') {
        /* [ipv6]:port */
        host = token + 1;
        t = strchr(host, ']');
        if (!t) {
            debugs(3, DBG_CRITICAL, s->protocol << "_port: missing ']' on IPv6 address: " << token);
            self_destruct();
        }
        *t = '\0';
        ++t;
        if (*t != ':') {
            debugs(3, DBG_CRITICAL, s->protocol << "_port: missing Port in: " << token);
            self_destruct();
        }
        if (!Ip::EnableIpv6) {
            debugs(3, DBG_CRITICAL, "FATAL: " << s->protocol << "_port: IPv6 is not available.");
            self_destruct();
        }
        port = xatos(t + 1);
    } else if ((t = strchr(token, ':'))) {
        /* host:port */
        /* ipv4:port */
        host = token;
        *t = '\0';
        port = xatos(t + 1);

    } else if (strtol(token, &junk, 10) && !*junk) {
        port = xatos(token);
        debugs(3, 3, s->protocol << "_port: found Listen on Port: " << port);
    } else {
        debugs(3, DBG_CRITICAL, s->protocol << "_port: missing Port: " << token);
        self_destruct();
    }

    if (port == 0 && host != NULL) {
        debugs(3, DBG_CRITICAL, s->protocol << "_port: Port cannot be 0: " << token);
        self_destruct();
    }

    if (NULL == host) {
        s->s.SetAnyAddr();
        s->s.SetPort(port);
        if (!Ip::EnableIpv6)
            s->s.SetIPv4();
        debugs(3, 3, s->protocol << "_port: found Listen on wildcard address: *:" << s->s.GetPort() );
    } else if ( (s->s = host) ) { /* check/parse numeric IPA */
        s->s.SetPort(port);
        if (!Ip::EnableIpv6)
            s->s.SetIPv4();
        debugs(3, 3, s->protocol << "_port: Listen on Host/IP: " << host << " --> " << s->s);
    } else if ( s->s.GetHostByName(host) ) { /* check/parse for FQDN */
        /* dont use ipcache */
        s->defaultsite = xstrdup(host);
        s->s.SetPort(port);
        if (!Ip::EnableIpv6)
            s->s.SetIPv4();
        debugs(3, 3, s->protocol << "_port: found Listen as Host " << s->defaultsite << " on IP: " << s->s);
    } else {
        debugs(3, DBG_CRITICAL, s->protocol << "_port: failed to resolve Host/IP: " << host);
        self_destruct();
    }
}

static void
parse_port_option(AnyP::PortCfg * s, char *token)
{
    /* modes first */

    if (strcmp(token, "accel") == 0) {
        if (s->intercepted || s->spoof_client_ip) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: Accelerator mode requires its own port. It cannot be shared with other modes.");
            self_destruct();
        }
        s->accel = s->vhost = 1;
    } else if (strcmp(token, "transparent") == 0 || strcmp(token, "intercept") == 0) {
        if (s->accel || s->spoof_client_ip) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: Intercept mode requires its own interception port. It cannot be shared with other modes.");
            self_destruct();
        }
        s->intercepted = 1;
        Ip::Interceptor.StartInterception();
        /* Log information regarding the port modes under interception. */
        debugs(3, DBG_IMPORTANT, "Starting Authentication on port " << s->s);
        debugs(3, DBG_IMPORTANT, "Disabling Authentication on port " << s->s << " (interception enabled)");

        /* INET6: until transparent REDIRECT works on IPv6 SOCKET, force wildcard to IPv4 */
        if (Ip::EnableIpv6)
            debugs(3, DBG_IMPORTANT, "Disabling IPv6 on port " << s->s << " (interception enabled)");
        if ( !s->s.SetIPv4() ) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: IPv6 addresses cannot NAT intercept (protocol does not provide NAT)" << s->s );
            self_destruct();
        }
    } else if (strcmp(token, "tproxy") == 0) {
        if (s->intercepted || s->accel) {
            debugs(3,DBG_CRITICAL, "FATAL: http(s)_port: TPROXY option requires its own interception port. It cannot be shared with other modes.");
            self_destruct();
        }
        s->spoof_client_ip = 1;
        Ip::Interceptor.StartTransparency();
        /* Log information regarding the port modes under transparency. */
        debugs(3, DBG_IMPORTANT, "Starting IP Spoofing on port " << s->s);
        debugs(3, DBG_IMPORTANT, "Disabling Authentication on port " << s->s << " (IP spoofing enabled)");

        if (!Ip::Interceptor.ProbeForTproxy(s->s)) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: TPROXY support in the system does not work.");
            self_destruct();
        }

    } else if (strncmp(token, "defaultsite=", 12) == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: defaultsite option requires Acceleration mode flag.");
            self_destruct();
        }
        safe_free(s->defaultsite);
        s->defaultsite = xstrdup(token + 12);
    } else if (strcmp(token, "vhost") == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "WARNING: http(s)_port: vhost option is deprecated. Use 'accel' mode flag instead.");
        }
        s->accel = s->vhost = 1;
    } else if (strcmp(token, "no-vhost") == 0) {
        if (!s->accel) {
            debugs(3, DBG_IMPORTANT, "ERROR: http(s)_port: no-vhost option requires Acceleration mode flag.");
        }
        s->vhost = 0;
    } else if (strcmp(token, "vport") == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: vport option requires Acceleration mode flag.");
            self_destruct();
        }
        s->vport = -1;
    } else if (strncmp(token, "vport=", 6) == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: vport option requires Acceleration mode flag.");
            self_destruct();
        }
        s->vport = xatos(token + 6);
    } else if (strncmp(token, "protocol=", 9) == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: protocol option requires Acceleration mode flag.");
            self_destruct();
        }
        s->protocol = xstrdup(token + 9);
    } else if (strcmp(token, "allow-direct") == 0) {
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: allow-direct option requires Acceleration mode flag.");
            self_destruct();
        }
        s->allow_direct = 1;
    } else if (strcmp(token, "act-as-origin") == 0) {
        if (!s->accel) {
            debugs(3, DBG_IMPORTANT, "ERROR: http(s)_port: act-as-origin option requires Acceleration mode flag.");
        } else
            s->actAsOrigin = 1;
    } else if (strcmp(token, "ignore-cc") == 0) {
#if !USE_HTTP_VIOLATIONS
        if (!s->accel) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: ignore-cc option requires Scceleration mode flag.");
            self_destruct();
        }
#endif
        s->ignore_cc = 1;
    } else if (strncmp(token, "name=", 5) == 0) {
        safe_free(s->name);
        s->name = xstrdup(token + 5);
    } else if (strcmp(token, "no-connection-auth") == 0) {
        s->connection_auth_disabled = true;
    } else if (strcmp(token, "connection-auth=off") == 0) {
        s->connection_auth_disabled = true;
    } else if (strcmp(token, "connection-auth") == 0) {
        s->connection_auth_disabled = false;
    } else if (strcmp(token, "connection-auth=on") == 0) {
        s->connection_auth_disabled = false;
    } else if (strncmp(token, "disable-pmtu-discovery=", 23) == 0) {
        if (!strcasecmp(token + 23, "off"))
            s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
        else if (!strcasecmp(token + 23, "transparent"))
            s->disable_pmtu_discovery = DISABLE_PMTU_TRANSPARENT;
        else if (!strcasecmp(token + 23, "always"))
            s->disable_pmtu_discovery = DISABLE_PMTU_ALWAYS;
        else
            self_destruct();
    } else if (strcmp(token, "ipv4") == 0) {
        if ( !s->s.SetIPv4() ) {
            debugs(3, DBG_CRITICAL, "FATAL: http(s)_port: IPv6 addresses cannot be used as IPv4-Only. " << s->s );
            self_destruct();
        }
    } else if (strcmp(token, "tcpkeepalive") == 0) {
        s->tcp_keepalive.enabled = 1;
    } else if (strncmp(token, "tcpkeepalive=", 13) == 0) {
        char *t = token + 13;
        s->tcp_keepalive.enabled = 1;
        s->tcp_keepalive.idle = xatoui(t);
        t = strchr(t, ',');
        if (t) {
            ++t;
            s->tcp_keepalive.interval = xatoui(t);
            t = strchr(t, ',');
        }
        if (t) {
            ++t;
            s->tcp_keepalive.timeout = xatoui(t);
            // t = strchr(t, ','); // not really needed, left in as documentation
        }
#if USE_SSL
    } else if (strcasecmp(token, "sslBump") == 0) {
        debugs(3, DBG_CRITICAL, "WARNING: '" << token << "' is deprecated " <<
               "in http_port. Use 'ssl-bump' instead.");
        s->sslBump = 1; // accelerated when bumped, otherwise not
    } else if (strcmp(token, "ssl-bump") == 0) {
        s->sslBump = 1; // accelerated when bumped, otherwise not
    } else if (strncmp(token, "cert=", 5) == 0) {
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
        safe_free(s->sslContextSessionId);
        s->sslContextSessionId = xstrdup(token + 11);
    } else if (strcmp(token, "generate-host-certificates") == 0) {
        s->generateHostCertificates = true;
    } else if (strcmp(token, "generate-host-certificates=on") == 0) {
        s->generateHostCertificates = true;
    } else if (strcmp(token, "generate-host-certificates=off") == 0) {
        s->generateHostCertificates = false;
    } else if (strncmp(token, "dynamic_cert_mem_cache_size=", 28) == 0) {
        parseBytesOptionValue(&s->dynamicCertMemCacheSize, B_BYTES_STR, token + 28);
#endif
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: Unknown http(s)_port option '" << token << "'.");
        self_destruct();
    }
}

void
add_http_port(char *portspec)
{
    AnyP::PortCfg *s = new AnyP::PortCfg("http_port");
    parsePortSpecification(s, portspec);
    // we may need to merge better if the above returns a list with clones
    assert(s->next == NULL);
    s->next = cbdataReference(Config.Sockaddr.http);
    cbdataReferenceDone(Config.Sockaddr.http);
    Config.Sockaddr.http = cbdataReference(s);
}

static void
parsePortCfg(AnyP::PortCfg ** head, const char *optionName)
{
    const char *protocol = NULL;
    if (strcmp(optionName, "http_port") == 0 ||
            strcmp(optionName, "ascii_port") == 0)
        protocol = "http";
    else if (strcmp(optionName, "https_port") == 0)
        protocol = "https";
    if (!protocol) {
        self_destruct();
        return;
    }

    char *token = strtok(NULL, w_space);

    if (!token) {
        self_destruct();
        return;
    }

    AnyP::PortCfg *s = new AnyP::PortCfg(protocol);
    parsePortSpecification(s, token);

    /* parse options ... */
    while ((token = strtok(NULL, w_space))) {
        parse_port_option(s, token);
    }

#if USE_SSL
    if (strcasecmp(protocol, "https") == 0) {
        /* ssl-bump on https_port configuration requires either tproxy or intercept, and vice versa */
        const bool hijacked = s->spoof_client_ip || s->intercepted;
        if (s->sslBump && !hijacked) {
            debugs(3, DBG_CRITICAL, "FATAL: ssl-bump on https_port requires tproxy/intercept which is missing.");
            self_destruct();
        }
        if (hijacked && !s->sslBump) {
            debugs(3, DBG_CRITICAL, "FATAL: tproxy/intercept on https_port requires ssl-bump which is missing.");
            self_destruct();
        }
    }
#endif

    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && s->s.IsAnyAddr()) {
        // clone the port options from *s to *(s->next)
        s->next = cbdataReference(s->clone());
        s->next->s.SetIPv4();
        debugs(3, 3, protocol << "_port: clone wildcard address for split-stack: " << s->s << " and " << s->next->s);
    }

    while (*head)
        head = &(*head)->next;

    *head = cbdataReference(s);
}

static void
dump_generic_port(StoreEntry * e, const char *n, const AnyP::PortCfg * s)
{
    char buf[MAX_IPSTRLEN];

    storeAppendPrintf(e, "%s %s",
                      n,
                      s->s.ToURL(buf,MAX_IPSTRLEN));

    // MODES and specific sub-options.
    if (s->intercepted)
        storeAppendPrintf(e, " intercept");

    else if (s->spoof_client_ip)
        storeAppendPrintf(e, " tproxy");

    else if (s->accel) {
        storeAppendPrintf(e, " accel");

        if (s->vhost)
            storeAppendPrintf(e, " vhost");

        if (s->vport < 0)
            storeAppendPrintf(e, " vport");
        else if (s->vport > 0)
            storeAppendPrintf(e, " vport=%d", s->vport);

        if (s->defaultsite)
            storeAppendPrintf(e, " defaultsite=%s", s->defaultsite);

        if (s->protocol && strcmp(s->protocol,"http") != 0)
            storeAppendPrintf(e, " protocol=%s", s->protocol);

        if (s->allow_direct)
            storeAppendPrintf(e, " allow-direct");

        if (s->ignore_cc)
            storeAppendPrintf(e, " ignore-cc");

    }

    // Generic independent options

    if (s->name)
        storeAppendPrintf(e, " name=%s", s->name);

#if USE_HTTP_VIOLATIONS
    if (!s->accel && s->ignore_cc)
        storeAppendPrintf(e, " ignore-cc");
#endif

    if (s->connection_auth_disabled)
        storeAppendPrintf(e, " connection-auth=off");
    else
        storeAppendPrintf(e, " connection-auth=on");

    if (s->disable_pmtu_discovery != DISABLE_PMTU_OFF) {
        const char *pmtu;

        if (s->disable_pmtu_discovery == DISABLE_PMTU_ALWAYS)
            pmtu = "always";
        else
            pmtu = "transparent";

        storeAppendPrintf(e, " disable-pmtu-discovery=%s", pmtu);
    }

    if (s->s.IsAnyAddr() && !s->s.IsIPv6())
        storeAppendPrintf(e, " ipv4");

    if (s->tcp_keepalive.enabled) {
        if (s->tcp_keepalive.idle || s->tcp_keepalive.interval || s->tcp_keepalive.timeout) {
            storeAppendPrintf(e, " tcpkeepalive=%d,%d,%d", s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);
        } else {
            storeAppendPrintf(e, " tcpkeepalive");
        }
    }

#if USE_SSL
    if (s->sslBump)
        storeAppendPrintf(e, " ssl-bump");

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

    if (s->sslContextSessionId)
        storeAppendPrintf(e, " sslcontext=%s", s->sslContextSessionId);

    if (s->generateHostCertificates)
        storeAppendPrintf(e, " generate-host-certificates");

    if (s->dynamicCertMemCacheSize != std::numeric_limits<size_t>::max())
        storeAppendPrintf(e, "dynamic_cert_mem_cache_size=%lu%s\n", (unsigned long)s->dynamicCertMemCacheSize, B_BYTES_STR);
#endif
}

static void
dump_PortCfg(StoreEntry * e, const char *n, const AnyP::PortCfg * s)
{
    while (s) {
        dump_generic_port(e, n, s);
        storeAppendPrintf(e, "\n");
        s = s->next;
    }
}

static void
free_PortCfg(AnyP::PortCfg ** head)
{
    AnyP::PortCfg *s;

    while ((s = *head) != NULL) {
        *head = s->next;
        cbdataReferenceDone(s);
    }
}

void
configFreeMemory(void)
{
    free_all();
#if USE_SSL
    SSL_CTX_free(Config.ssl_client.sslContext);
#endif
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
        debugs(0, DBG_CRITICAL, (opt_parse_cfg_only?"FATAL ":"") << "ERROR: " << name << " " << path << ": " << xstrerror());
        // keep going to find more issues if we are only checking the config file with "-k parse"
        if (opt_parse_cfg_only)
            return;
        // this is fatal if it is found during startup or reconfigure
        if (opt_send_signal == -1 || opt_send_signal == SIGHUP)
            fatalf("%s %s: %s", name, path, xstrerror());
    }
}

char *
strtokFile(void)
{
    return ConfigParser::strtokFile();
}

#include "AccessLogEntry.h"

static void
parse_access_log(CustomLog ** logs)
{
    const char *filename, *logdef_name;

    CustomLog *cl = (CustomLog *)xcalloc(1, sizeof(*cl));

    if ((filename = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(filename, "none") == 0) {
        cl->type = Log::Format::CLF_NONE;
        aclParseAclList(LegacyParser, &cl->aclList);
        while (*logs)
            logs = &(*logs)->next;
        *logs = cl;
        return;
    }

    if ((logdef_name = strtok(NULL, w_space)) == NULL)
        logdef_name = "squid";

    debugs(3, 9, "Log definition name '" << logdef_name << "' file '" << filename << "'");

    cl->filename = xstrdup(filename);

    /* look for the definition pointer corresponding to this name */
    Format::Format *lf = Log::TheConfig.logformats;

    while (lf != NULL) {
        debugs(3, 9, "Comparing against '" << lf->name << "'");

        if (strcmp(lf->name, logdef_name) == 0)
            break;

        lf = lf->next;
    }

    if (lf != NULL) {
        cl->type = Log::Format::CLF_CUSTOM;
        cl->logFormat = lf;
    } else if (strcmp(logdef_name, "auto") == 0) {
        debugs(0, DBG_CRITICAL, "WARNING: Log format 'auto' no longer exists. Using 'squid' instead.");
        cl->type = Log::Format::CLF_SQUID;
    } else if (strcmp(logdef_name, "squid") == 0) {
        cl->type = Log::Format::CLF_SQUID;
    } else if (strcmp(logdef_name, "common") == 0) {
        cl->type = Log::Format::CLF_COMMON;
    } else if (strcmp(logdef_name, "combined") == 0) {
        cl->type = Log::Format::CLF_COMBINED;
#if ICAP_CLIENT
    } else if (strcmp(logdef_name, "icap_squid") == 0) {
        cl->type = Log::Format::CLF_ICAP_SQUID;
#endif
    } else if (strcmp(logdef_name, "useragent") == 0) {
        cl->type = Log::Format::CLF_USERAGENT;
    } else if (strcmp(logdef_name, "referrer") == 0) {
        cl->type = Log::Format::CLF_REFERER;
    } else {
        debugs(3, DBG_CRITICAL, "Log format '" << logdef_name << "' is not defined");
        self_destruct();
        return;
    }

    aclParseAclList(LegacyParser, &cl->aclList);

    while (*logs)
        logs = &(*logs)->next;

    *logs = cl;
}

static int
check_null_access_log(CustomLog *customlog_definitions)
{
    return customlog_definitions == NULL;
}

static void
dump_access_log(StoreEntry * entry, const char *name, CustomLog * logs)
{
    CustomLog *log;

    for (log = logs; log; log = log->next) {
        storeAppendPrintf(entry, "%s ", name);

        switch (log->type) {

        case Log::Format::CLF_CUSTOM:
            storeAppendPrintf(entry, "%s %s", log->filename, log->logFormat->name);
            break;

        case Log::Format::CLF_NONE:
            storeAppendPrintf(entry, "none");
            break;

        case Log::Format::CLF_SQUID:
            storeAppendPrintf(entry, "%s squid", log->filename);
            break;

        case Log::Format::CLF_COMBINED:
            storeAppendPrintf(entry, "%s combined", log->filename);
            break;

        case Log::Format::CLF_COMMON:
            storeAppendPrintf(entry, "%s common", log->filename);
            break;

#if ICAP_CLIENT
        case Log::Format::CLF_ICAP_SQUID:
            storeAppendPrintf(entry, "%s icap_squid", log->filename);
            break;
#endif
        case Log::Format::CLF_USERAGENT:
            storeAppendPrintf(entry, "%s useragent", log->filename);
            break;

        case Log::Format::CLF_REFERER:
            storeAppendPrintf(entry, "%s referrer", log->filename);
            break;

        case Log::Format::CLF_UNKNOWN:
            break;
        }

        if (log->aclList)
            dump_acl_list(entry, log->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
free_access_log(CustomLog ** definitions)
{
    while (*definitions) {
        CustomLog *log = *definitions;
        *definitions = log->next;

        log->logFormat = NULL;
        log->type = Log::Format::CLF_UNKNOWN;

        if (log->aclList)
            aclDestroyAclList(&log->aclList);

        safe_free(log->filename);

        xfree(log);
    }
}

/// parses list of integers form name=N1,N2,N3,...
static bool
parseNamedIntList(const char *data, const String &name, Vector<int> &list)
{
    if (data && (strncmp(data, name.rawBuf(), name.size()) == 0)) {
        data += name.size();
        if (*data == '=') {
            while (true) {
                ++data;
                int value = 0;
                if (!StringToInt(data, value, &data, 10))
                    break;
                list.push_back(value);
                if (*data == '\0' || *data != ',')
                    break;
            }
        }
    }
    return data && *data == '\0';
}

static void
parse_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap)
{
#if !HAVE_CPU_AFFINITY
    debugs(3, DBG_CRITICAL, "FATAL: Squid built with no CPU affinity " <<
           "support, do not set 'cpu_affinity_map'");
    self_destruct();
#endif /* HAVE_CPU_AFFINITY */

    if (!*cpuAffinityMap)
        *cpuAffinityMap = new CpuAffinityMap;

    const char *const pToken = strtok(NULL, w_space);
    const char *const cToken = strtok(NULL, w_space);
    Vector<int> processes, cores;
    if (!parseNamedIntList(pToken, "process_numbers", processes)) {
        debugs(3, DBG_CRITICAL, "FATAL: bad 'process_numbers' parameter " <<
               "in 'cpu_affinity_map'");
        self_destruct();
    } else if (!parseNamedIntList(cToken, "cores", cores)) {
        debugs(3, DBG_CRITICAL, "FATAL: bad 'cores' parameter in " <<
               "'cpu_affinity_map'");
        self_destruct();
    } else if (!(*cpuAffinityMap)->add(processes, cores)) {
        debugs(3, DBG_CRITICAL, "FATAL: bad 'cpu_affinity_map'; " <<
               "process_numbers and cores lists differ in length or " <<
               "contain numbers <= 0");
        self_destruct();
    }
}

static void
dump_CpuAffinityMap(StoreEntry *const entry, const char *const name, const CpuAffinityMap *const cpuAffinityMap)
{
    if (cpuAffinityMap) {
        storeAppendPrintf(entry, "%s process_numbers=", name);
        for (size_t i = 0; i < cpuAffinityMap->processes().size(); ++i) {
            storeAppendPrintf(entry, "%s%i", (i ? "," : ""),
                              cpuAffinityMap->processes()[i]);
        }
        storeAppendPrintf(entry, " cores=");
        for (size_t i = 0; i < cpuAffinityMap->cores().size(); ++i) {
            storeAppendPrintf(entry, "%s%i", (i ? "," : ""),
                              cpuAffinityMap->cores()[i]);
        }
        storeAppendPrintf(entry, "\n");
    }
}

static void
free_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap)
{
    delete *cpuAffinityMap;
    *cpuAffinityMap = NULL;
}

#if USE_ADAPTATION

static void
parse_adaptation_service_set_type()
{
    Adaptation::Config::ParseServiceSet();
}

static void
parse_adaptation_service_chain_type()
{
    Adaptation::Config::ParseServiceChain();
}

static void
parse_adaptation_access_type()
{
    Adaptation::Config::ParseAccess(LegacyParser);
}

static void
parse_adaptation_meta_type(Adaptation::Config::MetaHeaders *)
{
    Adaptation::Config::ParseMetaHeader(LegacyParser);
}

static void
dump_adaptation_meta_type(StoreEntry *entry, const char *name, Adaptation::Config::MetaHeaders &)
{
    Adaptation::Config::DumpMetaHeader(entry, name);
}

static void
free_adaptation_meta_type(Adaptation::Config::MetaHeaders *)
{
    // Nothing to do, it is released inside Adaptation::Config::freeService()
}
#endif /* USE_ADAPTATION */

#if ICAP_CLIENT

static void
parse_icap_service_type(Adaptation::Icap::Config * cfg)
{
    cfg->parseService();
}

static void
free_icap_service_type(Adaptation::Icap::Config * cfg)
{
    cfg->freeService();
}

static void
dump_icap_service_type(StoreEntry * entry, const char *name, const Adaptation::Icap::Config &cfg)
{
    cfg.dumpService(entry, name);
}

static void
parse_icap_class_type()
{
    debugs(93, DBG_CRITICAL, "WARNING: 'icap_class' is depricated. " <<
           "Use 'adaptation_service_set' instead");
    Adaptation::Config::ParseServiceSet();
}

static void
parse_icap_access_type()
{
    debugs(93, DBG_CRITICAL, "WARNING: 'icap_access' is depricated. " <<
           "Use 'adaptation_access' instead");
    Adaptation::Config::ParseAccess(LegacyParser);
}

#endif

#if USE_ECAP

static void
parse_ecap_service_type(Adaptation::Ecap::Config * cfg)
{
    cfg->parseService();
}

static void
free_ecap_service_type(Adaptation::Ecap::Config * cfg)
{
    cfg->freeService();
}

static void
dump_ecap_service_type(StoreEntry * entry, const char *name, const Adaptation::Ecap::Config &cfg)
{
    cfg.dumpService(entry, name);
}

#endif /* USE_ECAP */

#if ICAP_CLIENT
static void parse_icap_service_failure_limit(Adaptation::Icap::Config *cfg)
{
    char *token;
    time_t d;
    time_t m;
    cfg->service_failure_limit = GetInteger();

    if ((token = strtok(NULL, w_space)) == NULL)
        return;

    if (strcmp(token,"in") != 0) {
        debugs(3, DBG_CRITICAL, "expecting 'in' on'"  << config_input_line << "'");
        self_destruct();
    }

    if ((token = strtok(NULL, w_space)) == NULL) {
        self_destruct();
    }

    d = static_cast<time_t> (xatoi(token));

    m = static_cast<time_t> (1);

    if (0 == d)
        (void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL) {
        debugs(3, DBG_CRITICAL, "No time-units on '" << config_input_line << "'");
        self_destruct();
    } else if ((m = parseTimeUnits(token, false)) == 0)
        self_destruct();

    cfg->oldest_service_failure = (m * d);
}

static void dump_icap_service_failure_limit(StoreEntry *entry, const char *name, const Adaptation::Icap::Config &cfg)
{
    storeAppendPrintf(entry, "%s %d", name, cfg.service_failure_limit);
    if (cfg.oldest_service_failure > 0) {
        storeAppendPrintf(entry, " in %d seconds", (int)cfg.oldest_service_failure);
    }
    storeAppendPrintf(entry, "\n");
}

static void free_icap_service_failure_limit(Adaptation::Icap::Config *cfg)
{
    cfg->oldest_service_failure = 0;
    cfg->service_failure_limit = 0;
}
#endif

#if USE_SSL
static void parse_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt)
{
    char *al;
    sslproxy_cert_adapt *ca = (sslproxy_cert_adapt *) xcalloc(1, sizeof(sslproxy_cert_adapt));
    if ((al = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    const char *param;
    if ( char *s = strchr(al, '{')) {
        *s = '\0'; // terminate the al string
        ++s;
        param = s;
        s = strchr(s, '}');
        if (!s) {
            self_destruct();
            return;
        }
        *s = '\0';
    } else
        param = NULL;

    if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetValidAfter]) == 0) {
        ca->alg = Ssl::algSetValidAfter;
        ca->param = strdup("on");
    } else if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetValidBefore]) == 0) {
        ca->alg = Ssl::algSetValidBefore;
        ca->param = strdup("on");
    } else if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetCommonName]) == 0) {
        ca->alg = Ssl::algSetCommonName;
        if (param) {
            if (strlen(param) > 64) {
                debugs(3, DBG_CRITICAL, "FATAL: sslproxy_cert_adapt: setCommonName{" <<param << "} : using common name longer than 64 bytes is not supported");
                self_destruct();
                return;
            }
            ca->param = strdup(param);
        }
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: sslproxy_cert_adapt: unknown cert adaptation algorithm: " << al);
        self_destruct();
        return;
    }

    aclParseAclList(LegacyParser, &ca->aclList);

    while (*cert_adapt)
        cert_adapt = &(*cert_adapt)->next;

    *cert_adapt = ca;
}

static void dump_sslproxy_cert_adapt(StoreEntry *entry, const char *name, sslproxy_cert_adapt *cert_adapt)
{
    for (sslproxy_cert_adapt *ca = cert_adapt; ca != NULL; ca = ca->next) {
        storeAppendPrintf(entry, "%s ", name);
        storeAppendPrintf(entry, "%s{%s} ", Ssl::sslCertAdaptAlgoritm(ca->alg), ca->param);
        if (ca->aclList)
            dump_acl_list(entry, ca->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void free_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt)
{
    while (*cert_adapt) {
        sslproxy_cert_adapt *ca = *cert_adapt;
        *cert_adapt = ca->next;
        safe_free(ca->param);

        if (ca->aclList)
            aclDestroyAclList(&ca->aclList);

        safe_free(ca);
    }
}

static void parse_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign)
{
    char *al;
    sslproxy_cert_sign *cs = (sslproxy_cert_sign *) xcalloc(1, sizeof(sslproxy_cert_sign));
    if ((al = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    if (strcmp(al, Ssl::CertSignAlgorithmStr[Ssl::algSignTrusted]) == 0)
        cs->alg = Ssl::algSignTrusted;
    else if (strcmp(al, Ssl::CertSignAlgorithmStr[Ssl::algSignUntrusted]) == 0)
        cs->alg = Ssl::algSignUntrusted;
    else if (strcmp(al, Ssl::CertSignAlgorithmStr[Ssl::algSignSelf]) == 0)
        cs->alg = Ssl::algSignSelf;
    else {
        debugs(3, DBG_CRITICAL, "FATAL: sslproxy_cert_sign: unknown cert signing algorithm: " << al);
        self_destruct();
        return;
    }

    aclParseAclList(LegacyParser, &cs->aclList);

    while (*cert_sign)
        cert_sign = &(*cert_sign)->next;

    *cert_sign = cs;
}

static void dump_sslproxy_cert_sign(StoreEntry *entry, const char *name, sslproxy_cert_sign *cert_sign)
{
    sslproxy_cert_sign *cs;
    for (cs = cert_sign; cs != NULL; cs = cs->next) {
        storeAppendPrintf(entry, "%s ", name);
        storeAppendPrintf(entry, "%s ", Ssl::certSignAlgorithm(cs->alg));
        if (cs->aclList)
            dump_acl_list(entry, cs->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void free_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign)
{
    while (*cert_sign) {
        sslproxy_cert_sign *cs = *cert_sign;
        *cert_sign = cs->next;

        if (cs->aclList)
            aclDestroyAclList(&cs->aclList);

        safe_free(cs);
    }
}

class sslBumpCfgRr: public ::RegisteredRunner
{
public:
    static Ssl::BumpMode lastDeprecatedRule;
    /* RegisteredRunner API */
    virtual void run(const RunnerRegistry &);
};

Ssl::BumpMode sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpEnd;

RunnerRegistrationEntry(rrFinalizeConfig, sslBumpCfgRr);

void sslBumpCfgRr::run(const RunnerRegistry &r)
{
    if (lastDeprecatedRule != Ssl::bumpEnd) {
        assert( lastDeprecatedRule == Ssl::bumpClientFirst || lastDeprecatedRule == Ssl::bumpNone);
        static char buf[1024];
        if (lastDeprecatedRule == Ssl::bumpClientFirst) {
            strcpy(buf, "ssl_bump deny all");
            debugs(3, DBG_CRITICAL, "WARNING: auto-converting deprecated implicit "
                   "\"ssl_bump deny all\" to \"ssl_bump none all\". New ssl_bump configurations "
                   "must not use implicit rules. Update your ssl_bump rules.");
        } else {
            strcpy(buf, "ssl_bump allow all");
            debugs(3, DBG_CRITICAL, "SECURITY NOTICE: auto-converting deprecated implicit "
                   "\"ssl_bump allow all\" to \"ssl_bump client-first all\" which is usually "
                   "inferior to the newer server-first bumping mode. New ssl_bump"
                   " configurations must not use implicit rules. Update your ssl_bump rules.");
        }
        parse_line(buf);
    }
}

static void parse_sslproxy_ssl_bump(acl_access **ssl_bump)
{
    typedef const char *BumpCfgStyle;
    BumpCfgStyle bcsNone = NULL;
    BumpCfgStyle bcsNew = "new client/server-first/none";
    BumpCfgStyle bcsOld = "deprecated allow/deny";
    static BumpCfgStyle bumpCfgStyleLast = bcsNone;
    BumpCfgStyle bumpCfgStyleNow = bcsNone;
    char *bm;
    if ((bm = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }

    // if this is the first rule proccessed
    if (*ssl_bump == NULL) {
        bumpCfgStyleLast = bcsNone;
        sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpEnd;
    }

    acl_access *A = new acl_access;
    A->allow = allow_t(ACCESS_ALLOWED);

    if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpClientFirst]) == 0) {
        A->allow.kind = Ssl::bumpClientFirst;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpServerFirst]) == 0) {
        A->allow.kind = Ssl::bumpServerFirst;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpNone]) == 0) {
        A->allow.kind = Ssl::bumpNone;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, "allow") == 0) {
        debugs(3, DBG_CRITICAL, "SECURITY NOTICE: auto-converting deprecated "
               "\"ssl_bump allow <acl>\" to \"ssl_bump client-first <acl>\" which "
               "is usually inferior to the newer server-first "
               "bumping mode. Update your ssl_bump rules.");
        A->allow.kind = Ssl::bumpClientFirst;
        bumpCfgStyleNow = bcsOld;
        sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpClientFirst;
    } else if (strcmp(bm, "deny") == 0) {
        debugs(3, DBG_CRITICAL, "WARNING: auto-converting deprecated "
               "\"ssl_bump deny <acl>\" to \"ssl_bump none <acl>\". Update "
               "your ssl_bump rules.");
        A->allow.kind = Ssl::bumpNone;
        bumpCfgStyleNow = bcsOld;
        sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpNone;
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: unknown ssl_bump mode: " << bm);
        self_destruct();
        return;
    }

    if (bumpCfgStyleLast != bcsNone && bumpCfgStyleNow != bumpCfgStyleLast) {
        debugs(3, DBG_CRITICAL, "FATAL: do not mix " << bumpCfgStyleNow << " actions with " <<
               bumpCfgStyleLast << " actions. Update your ssl_bump rules.");
        self_destruct();
        return;
    }

    bumpCfgStyleLast = bumpCfgStyleNow;

    aclParseAclList(LegacyParser, &A->aclList);

    acl_access *B, **T;
    for (B = *ssl_bump, T = ssl_bump; B; T = &B->next, B = B->next);
    *T = A;
}

static void dump_sslproxy_ssl_bump(StoreEntry *entry, const char *name, acl_access *ssl_bump)
{
    acl_access *sb;
    for (sb = ssl_bump; sb != NULL; sb = sb->next) {
        storeAppendPrintf(entry, "%s ", name);
        storeAppendPrintf(entry, "%s ", Ssl::bumpMode(sb->allow.kind));
        if (sb->aclList)
            dump_acl_list(entry, sb->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void free_sslproxy_ssl_bump(acl_access **ssl_bump)
{
    free_acl_access(ssl_bump);
}

#endif

static void dump_HeaderWithAclList(StoreEntry * entry, const char *name, HeaderWithAclList *headers)
{
    if (!headers)
        return;

    for (HeaderWithAclList::iterator hwa = headers->begin(); hwa != headers->end(); ++hwa) {
        storeAppendPrintf(entry, "%s ", hwa->fieldName.c_str());
        storeAppendPrintf(entry, "%s ", hwa->fieldValue.c_str());
        if (hwa->aclList)
            dump_acl_list(entry, hwa->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void parse_HeaderWithAclList(HeaderWithAclList **headers)
{
    char *fn;
    if (!*headers) {
        *headers = new HeaderWithAclList;
    }
    if ((fn = strtok(NULL, w_space)) == NULL) {
        self_destruct();
        return;
    }
    HeaderWithAcl hwa;
    hwa.fieldName = fn;
    hwa.fieldId = httpHeaderIdByNameDef(fn, strlen(fn));
    if (hwa.fieldId == HDR_BAD_HDR)
        hwa.fieldId = HDR_OTHER;

    String buf;
    bool wasQuoted;
    ConfigParser::ParseQuotedString(&buf, &wasQuoted);
    hwa.fieldValue = buf.termedBuf();
    hwa.quoted = wasQuoted;
    if (hwa.quoted) {
        Format::Format *nlf =  new ::Format::Format("hdrWithAcl");
        if (!nlf->parse(hwa.fieldValue.c_str())) {
            self_destruct();
            return;
        }
        hwa.valueFormat = nlf;
    }
    aclParseAclList(LegacyParser, &hwa.aclList);
    (*headers)->push_back(hwa);
}

static void free_HeaderWithAclList(HeaderWithAclList **header)
{
    if (!(*header))
        return;

    for (HeaderWithAclList::iterator hwa = (*header)->begin(); hwa != (*header)->end(); ++hwa) {
        if (hwa->aclList)
            aclDestroyAclList(&hwa->aclList);

        if (hwa->valueFormat) {
            delete hwa->valueFormat;
            hwa->valueFormat = NULL;
        }
    }
    delete *header;
    *header = NULL;
}
