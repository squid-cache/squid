/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/AclDenyInfoList.h"
#include "acl/AclSizeLimit.h"
#include "acl/Address.h"
#include "acl/Gadgets.h"
#include "acl/MethodData.h"
#include "acl/Tree.h"
#include "anyp/PortCfg.h"
#include "anyp/UriScheme.h"
#include "auth/Config.h"
#include "auth/Scheme.h"
#include "AuthReg.h"
#include "base/PackableStream.h"
#include "base/RunnersRegistry.h"
#include "cache_cf.h"
#include "CachePeer.h"
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "CpuAffinityMap.h"
#include "debug/Messages.h"
#include "DiskIO/DiskIOModule.h"
#include "eui/Config.h"
#include "ExternalACL.h"
#include "format/Format.h"
#include "fqdncache.h"
#include "ftp/Elements.h"
#include "globals.h"
#include "HttpHeaderTools.h"
#include "HttpUpgradeProtocolAccess.h"
#include "icmp/IcmpConfig.h"
#include "ident/Config.h"
#include "ip/Intercept.h"
#include "ip/NfMarkConfig.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "ipc/Kids.h"
#include "log/Config.h"
#include "log/CustomLog.h"
#include "MemBuf.h"
#include "MessageDelayPools.h"
#include "mgr/ActionPasswordList.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "Parsing.h"
#include "pconn.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "redirect.h"
#include "RefreshPattern.h"
#include "rfc1738.h"
#include "sbuf/List.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "ssl/ProxyCerts.h"
#include "Store.h"
#include "store/Disks.h"
#include "tools.h"
#include "util.h"
#include "wordlist.h"
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
#if USE_OPENSSL
#include "ssl/Config.h"
#include "ssl/support.h"
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
#include <chrono>
#include <limits>
#include <list>
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

#if USE_ADAPTATION
static void parse_adaptation_service_set_type();
static void parse_adaptation_service_chain_type();
static void parse_adaptation_access_type();
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

static const char *const T_NANOSECOND_STR = "nanosecond";
static const char *const T_MICROSECOND_STR = "microsecond";
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

// std::chrono::years requires C++20. Do our own rough calculation for now.
static const double HoursPerYear = 24*365.2522;

static void parse_cache_log_message(DebugMessages **messages);
static void dump_cache_log_message(StoreEntry *entry, const char *name, const DebugMessages *messages);
static void free_cache_log_message(DebugMessages **messages);

static void parse_access_log(CustomLog ** customlog_definitions);
static int check_null_access_log(CustomLog *customlog_definitions);
static void dump_access_log(StoreEntry * entry, const char *name, CustomLog * definitions);
static void free_access_log(CustomLog ** definitions);

static void configDoConfigure(void);
static void parse_refreshpattern(RefreshPattern **);
static void parse_u_short(unsigned short * var);
static void parse_string(char **);
static void default_all(void);
static void defaults_if_none(void);
static void defaults_postscriptum(void);
static int parse_line(char *);
static void parse_obsolete(const char *);
static void parseBytesLine(size_t * bptr, const char *units);
static void parseBytesLineSigned(ssize_t * bptr, const char *units);
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
static void parse_note(Notes *);
static void dump_note(StoreEntry *, const char *, Notes &);
static void free_note(Notes *);
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

static void parsePortCfg(AnyP::PortCfgPointer *, const char *protocol);
#define parse_PortCfg(l) parsePortCfg((l), token)
static void dump_PortCfg(StoreEntry *, const char *, const AnyP::PortCfgPointer &);
#define free_PortCfg(h)  *(h)=NULL

#if USE_OPENSSL
static void parse_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign);
static void dump_sslproxy_cert_sign(StoreEntry *entry, const char *name, sslproxy_cert_sign *cert_sign);
static void free_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign);
static void parse_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt);
static void dump_sslproxy_cert_adapt(StoreEntry *entry, const char *name, sslproxy_cert_adapt *cert_adapt);
static void free_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt);
static void parse_sslproxy_ssl_bump(acl_access **ssl_bump);
static void dump_sslproxy_ssl_bump(StoreEntry *entry, const char *name, acl_access *ssl_bump);
static void free_sslproxy_ssl_bump(acl_access **ssl_bump);
#endif /* USE_OPENSSL */

static void parse_ftp_epsv(acl_access **ftp_epsv);
static void dump_ftp_epsv(StoreEntry *entry, const char *name, acl_access *ftp_epsv);
static void free_ftp_epsv(acl_access **ftp_epsv);

static void parse_b_size_t(size_t * var);
static void parse_b_int64_t(int64_t * var);

static void parse_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap);
static void dump_CpuAffinityMap(StoreEntry *const entry, const char *const name, const CpuAffinityMap *const cpuAffinityMap);
static void free_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap);

static void parse_UrlHelperTimeout(SquidConfig::UrlHelperTimeout *);
static void dump_UrlHelperTimeout(StoreEntry *, const char *, SquidConfig::UrlHelperTimeout &);
static void free_UrlHelperTimeout(SquidConfig::UrlHelperTimeout *);

static int parseOneConfigFile(const char *file_name, unsigned int depth);

static void parse_configuration_includes_quoted_values(bool *recognizeQuotedValues);
static void dump_configuration_includes_quoted_values(StoreEntry *const entry, const char *const name, bool recognizeQuotedValues);
static void free_configuration_includes_quoted_values(bool *recognizeQuotedValues);
static void parse_on_unsupported_protocol(acl_access **access);
static void dump_on_unsupported_protocol(StoreEntry *entry, const char *name, acl_access *access);
static void free_on_unsupported_protocol(acl_access **access);
static void ParseAclWithAction(acl_access **access, const Acl::Answer &action, const char *desc, ACL *acl = nullptr);
static void parse_http_upgrade_request_protocols(HttpUpgradeProtocolAccess **protoGuards);
static void dump_http_upgrade_request_protocols(StoreEntry *entry, const char *name, HttpUpgradeProtocolAccess *protoGuards);
static void free_http_upgrade_request_protocols(HttpUpgradeProtocolAccess **protoGuards);

/*
 * LegacyParser is a parser for legacy code that uses the global
 * approach.  This is static so that it is only exposed to cache_cf.
 * Other modules needing access to a ConfigParser should have it
 * provided to them in their parserFOO methods.
 */
static ConfigParser LegacyParser = ConfigParser();

const char *cfg_directive = nullptr;
const char *cfg_filename = nullptr;
int config_lineno = 0;
char config_input_line[BUFSIZ] = {};

void
self_destruct(void)
{
    LegacyParser.destruct();
}

static void
SetConfigFilename(char const *file_name, bool is_pipe)
{
    if (is_pipe)
        cfg_filename = file_name + 1;
    else
        cfg_filename = file_name;
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
    char* saveptr = nullptr;
#if HAVE_GLOB
    char *path;
    glob_t globbuf;
    int i;
    memset(&globbuf, 0, sizeof(globbuf));
    for (path = strwordtok(files, &saveptr); path; path = strwordtok(nullptr, &saveptr)) {
        if (glob(path, globbuf.gl_pathc ? GLOB_APPEND : 0, nullptr, &globbuf) != 0) {
            int xerrno = errno;
            fatalf("Unable to find configuration file: %s: %s", path, xstrerr(xerrno));
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
        file = strwordtok(nullptr, &saveptr);
    }
#endif /* HAVE_GLOB */
    return error_count;
}

static void
ReplaceSubstr(char*& str, int& len, unsigned substrIdx, unsigned substrLen, const char* newSubstr)
{
    assert(str != nullptr);
    assert(newSubstr != nullptr);

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
    assert(line != nullptr);
    assert(macroName != nullptr);
    assert(substStr != nullptr);
    unsigned macroNameLen = strlen(macroName);
    while (const char* macroPos = strstr(line, macroName)) // we would replace all occurrences
        ReplaceSubstr(line, len, macroPos - line, macroNameLen, substStr);
}

static void
ProcessMacros(char*& line, int& len)
{
    SubstituteMacro(line, len, "${service_name}", service_name.c_str());
    SubstituteMacro(line, len, "${process_name}", TheKidName.c_str());
    SubstituteMacro(line, len, "${process_number}", xitoa(KidIdentifier));
}

static void
trim_trailing_ws(char* str)
{
    assert(str != nullptr);
    unsigned i = strlen(str);
    while ((i > 0) && xisspace(str[i - 1]))
        --i;
    str[i] = '\0';
}

static const char*
FindStatement(const char* line, const char* statement)
{
    assert(line != nullptr);
    assert(statement != nullptr);

    const char* str = skip_ws(line);
    unsigned len = strlen(statement);
    if (strncmp(str, statement, len) == 0) {
        str += len;
        if (*str == '\0')
            return str;
        else if (xisspace(*str))
            return skip_ws(str);
    }

    return nullptr;
}

static bool
StrToInt(const char* str, long& number)
{
    assert(str != nullptr);

    char* end;
    number = strtol(str, &end, 0);

    return (end != str) && (*end == '\0'); // returns true if string contains nothing except number
}

static bool
EvalBoolExpr(const char* expr)
{
    assert(expr != nullptr);
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
    FILE *fp = nullptr;
    const char *orig_cfg_filename = cfg_filename;
    const int orig_config_lineno = config_lineno;
    char *token = nullptr;
    char *tmp_line = nullptr;
    int tmp_line_len = 0;
    int err_count = 0;
    int is_pipe = 0;

    debugs(3, Important(68), "Processing Configuration File: " << file_name << " (depth " << depth << ")");
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

    if (!fp) {
        int xerrno = errno;
        fatalf("Unable to open configuration file: %s: %s", file_name, xstrerr(xerrno));
    }

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    SetConfigFilename(file_name, bool(is_pipe));

    memset(config_input_line, '\0', BUFSIZ);

    config_lineno = 0;

    std::vector<bool> if_states;
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
                continue;   /* Not a valid #line directive, may be a comment */

            while (*file && xisspace((unsigned char) *file))
                ++file;

            if (*file) {
                if (*file != '"')
                    continue;   /* Not a valid #line directive, may be a comment */

                xstrncpy(new_file_name, file + 1, sizeof(new_file_name));

                if ((token = strchr(new_file_name, '"')))
                    *token = '\0';

                SetConfigFilename(new_file_name, false);
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
            } else {
                try {
                    if (!parse_line(tmp_line)) {
                        debugs(3, DBG_CRITICAL, ConfigParser::CurrentLocation() << ": unrecognized: '" << tmp_line << "'");
                        ++err_count;
                    }
                } catch (...) {
                    // fatal for now
                    debugs(3, DBG_CRITICAL, "ERROR: configuration failure: " << CurrentException);
                    self_destruct();
                }
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

    SetConfigFilename(orig_cfg_filename, false);
    config_lineno = orig_config_lineno;

    xfree(tmp_line);
    return err_count;
}

static
int
parseConfigFileOrThrow(const char *file_name)
{
    int err_count = 0;

    debugs(5, 4, MYNAME);

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

    if (opt_send_signal == -1) {
        Mgr::RegisterAction("config",
                            "Current Squid Configuration",
                            dump_config,
                            1, 1);
    }

    return err_count;
}

// TODO: Refactor main.cc to centrally handle (and report) all exceptions.
int
parseConfigFile(const char *file_name)
{
    try {
        return parseConfigFileOrThrow(file_name);
    }
    catch (const std::exception &ex) {
        debugs(3, DBG_CRITICAL, "FATAL: bad configuration: " << ex.what());
        self_destruct();
        return 1; // not reached
    }
}

/*
 * The templated functions below are essentially ConfigParser methods. They are
 * not implemented as such because our generated code calling them is the only
 * code that can instantiate implementations for each T -- we cannot place these
 * definitions into ConfigParser.cc unless cf_parser.cci is moved there.
 */

// TODO: When adding Ts incompatible with this trivial API and implementation,
// replace both with a ConfigParser-maintained table of seen directives.
/// whether we have seen (and, hence, configured) the given directive
template <typename T>
static bool
SawDirective(const T &raw)
{
    return bool(raw);
}

/// Sets the given raw SquidConfig data member.
/// Extracts and interprets parser's configuration tokens.
template <typename T>
static void
ParseDirective(T &raw, ConfigParser &parser)
{
    if (SawDirective(raw))
        parser.rejectDuplicateDirective();

    // TODO: parser.openDirective(directiveName);
    Must(!raw);
    raw = Configuration::Component<T>::Parse(parser);
    Must(raw);
    parser.closeDirective();
}

/// reports raw SquidConfig data member configuration using squid.conf syntax
/// \param name the name of the configuration directive being dumped
template <typename T>
static void
DumpDirective(const T &raw, StoreEntry *entry, const char *name)
{
    if (!SawDirective(raw))
        return; // not configured

    entry->append(name, strlen(name));
    SBufStream os;
    Configuration::Component<T>::Print(os, raw);
    const auto buf = os.buf();
    if (buf.length()) {
        entry->append(" ", 1);
        entry->append(buf.rawContent(), buf.length());
    }
    entry->append("\n", 1);
}

/// frees any resources associated with the given raw SquidConfig data member
template <typename T>
static void
FreeDirective(T &raw)
{
    Configuration::Component<T>::Free(raw);

    // While the implementation may change, there is no way to avoid zeroing.
    // Even migration to a proper SquidConfig class would not help: While
    // ordinary destructors do not need to zero data members, a SquidConfig
    // destructor would have to zero to protect any SquidConfig::x destruction
    // code from accidentally dereferencing an already destroyed Config.y.
    static_assert(std::is_trivial<T>::value, "SquidConfig member is trivial");
    memset(&raw, 0, sizeof(raw));
}

static void
configDoConfigure(void)
{
    Config2.clear();
    /* init memory as early as possible */
    memConfigure();
    /* Sanity checks */

    if (Debug::rotateNumber < 0) {
        Debug::rotateNumber = Config.Log.rotateNumber;
    }

#if SIZEOF_OFF_T <= 4
    if (Config.Store.maxObjectSize > 0x7FFF0000) {
        debugs(3, DBG_CRITICAL, "WARNING: This Squid binary can not handle files larger than 2GB. Limiting maximum_object_size to just below 2GB");
        Config.Store.maxObjectSize = 0x7FFF0000;
    }
#endif

    if (Config.onoff.httpd_suppress_version_string)
        visible_appname_string = (char *)appname_string;
    else
        visible_appname_string = (char const *)APP_FULLNAME;

    if (Config.Program.redirect) {
        if (Config.redirectChildren.n_max < 1) {
            Config.redirectChildren.n_max = 0;
            wordlistDestroy(&Config.Program.redirect);
        }
    }

    if (Config.Program.store_id) {
        if (Config.storeIdChildren.n_max < 1) {
            Config.storeIdChildren.n_max = 0;
            wordlistDestroy(&Config.Program.store_id);
        }
    }

    if (Config.appendDomain)
        if (*Config.appendDomain != '.')
            fatal("append_domain must begin with a '.'");

    if (Config.errHtmlText == nullptr)
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
    snprintf(ThisCache2, sizeof(ThisCache2), " %s (%s)",
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
#if USE_UNLINKD

    requirePathnameExists("unlinkd_program", Config.Program.unlinkd);
#endif
    bool logDaemonUsed = false;
    for (const auto *log = Config.Log.accesslogs; !logDaemonUsed && log; log = log->next)
        logDaemonUsed = log->usesDaemon();
#if ICAP_CLIENT
    for (const auto *log = Config.Log.icaplogs; !logDaemonUsed && log; log = log->next)
        logDaemonUsed = log->usesDaemon();
#endif
    if (logDaemonUsed)
        requirePathnameExists("logfile_daemon", Log::TheConfig.logfile_daemon);

    if (Config.Program.redirect)
        requirePathnameExists("redirect_program", Config.Program.redirect->key);

    if (Config.Program.store_id)
        requirePathnameExists("store_id_program", Config.Program.store_id->key);

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
            if (!R->flags.ignore_private)
                continue;

            debugs(22, DBG_IMPORTANT, "WARNING: use of 'ignore-private' in 'refresh_pattern' violates HTTP");

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

    if (geteuid() == 0) {
        if (nullptr != Config.effectiveUser) {

            struct passwd *pwd = getpwnam(Config.effectiveUser);

            if (nullptr == pwd) {
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
                // putenv() leaks by design; avoid leaks when nothing changes
                static SBuf lastDir;
                if (lastDir.isEmpty() || lastDir.cmp(pwd->pw_dir) != 0) {
                    lastDir = pwd->pw_dir;
                    int len = strlen(pwd->pw_dir) + 6;
                    char *env_str = (char *)xcalloc(len, 1);
                    snprintf(env_str, len, "HOME=%s", pwd->pw_dir);
                    putenv(env_str);
                }
            }
#endif
        }
    } else {
        Config2.effectiveUserID = geteuid();
        Config2.effectiveGroupID = getegid();
    }

    if (nullptr != Config.effectiveGroup) {

        struct group *grp = getgrnam(Config.effectiveGroup);

        if (nullptr == grp) {
            fatalf("getgrnam failed to find groupid for effective group '%s'",
                   Config.effectiveGroup);
            return;
        }

        Config2.effectiveGroupID = grp->gr_gid;
    }

#if USE_OPENSSL
    if (Config.ssl_client.foreignIntermediateCertsPath)
        Ssl::loadSquidUntrusted(Config.ssl_client.foreignIntermediateCertsPath);
#endif

    if (Security::ProxyOutgoingConfig.encryptTransport) {
        debugs(3, 2, "initializing https:// proxy context");
        Config.ssl_client.sslContext = Security::ProxyOutgoingConfig.createClientContext(false);
        if (!Config.ssl_client.sslContext) {
#if USE_OPENSSL
            fatal("ERROR: Could not initialize https:// proxy context");
#else
            debugs(3, DBG_IMPORTANT, "ERROR: proxying https:// currently still requires --with-openssl");
#endif
        }
#if USE_OPENSSL
        Ssl::useSquidUntrusted(Config.ssl_client.sslContext.get());
#endif
    }

    for (CachePeer *p = Config.peers; p != nullptr; p = p->next) {

        // default value for ssldomain= is the peer host/IP
        if (p->secure.sslDomain.isEmpty())
            p->secure.sslDomain = p->host;

        if (p->secure.encryptTransport) {
            debugs(3, 2, "initializing TLS context for cache_peer " << *p);
            p->sslContext = p->secure.createClientContext(true);
            if (!p->sslContext) {
                debugs(3, DBG_CRITICAL, "ERROR: Could not initialize TLS context for cache_peer " << *p);
                self_destruct();
                return;
            }
        }
    }

    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (!s->secure.encryptTransport)
            continue;
        debugs(3, 2, "initializing " << AnyP::UriScheme(s->transport.protocol) << "_port " << s->s << " TLS contexts");
        s->secure.initServerContexts(*s);
    }

    // prevent infinite fetch loops in the request parser
    // due to buffer full but not enough data received to finish parse
    if (Config.maxRequestBufferSize <= Config.maxRequestHeaderSize) {
        fatalf("Client request buffer of %u bytes cannot hold a request with %u bytes of headers." \
               " Change client_request_buffer_max or request_header_max_size limits.",
               (uint32_t)Config.maxRequestBufferSize, (uint32_t)Config.maxRequestHeaderSize);
    }

    // Warn about the dangers of exceeding String limits when manipulating HTTP
    // headers. Technically, we do not concatenate _requests_, so we could relax
    // their check, but we keep the two checks the same for simplicity sake.
    const auto safeRawHeaderValueSizeMax = (String::SizeMaxXXX()+1)/3;
    // TODO: static_assert(safeRawHeaderValueSizeMax >= 64*1024); // no WARNINGs for default settings
    if (Config.maxRequestHeaderSize > safeRawHeaderValueSizeMax)
        debugs(3, DBG_CRITICAL, "WARNING: Increasing request_header_max_size beyond " << safeRawHeaderValueSizeMax <<
               " bytes makes Squid more vulnerable to denial-of-service attacks; configured value: " << Config.maxRequestHeaderSize << " bytes");
    if (Config.maxReplyHeaderSize > safeRawHeaderValueSizeMax)
        debugs(3, DBG_CRITICAL, "WARNING: Increasing reply_header_max_size beyond " << safeRawHeaderValueSizeMax <<
               " bytes makes Squid more vulnerable to denial-of-service attacks; configured value: " << Config.maxReplyHeaderSize << " bytes");

    /*
     * Disable client side request pipelining if client_persistent_connections OFF.
     * Waste of resources queueing any pipelined requests when the first will close the connection.
     */
    if (Config.pipeline_max_prefetch > 0 && !Config.onoff.client_pconns) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: pipeline_prefetch " << Config.pipeline_max_prefetch <<
               " requires client_persistent_connections ON. Forced pipeline_prefetch 0.");
        Config.pipeline_max_prefetch = 0;
    }

#if USE_AUTH
    /*
     * disable client side request pipelining. There is a race with
     * Negotiate and NTLM when the client sends a second request on an
     * connection before the authenticate challenge is sent. With
     * pipelining OFF, the client may fail to authenticate, but squid's
     * state will be preserved.
     */
    if (Config.pipeline_max_prefetch > 0) {
        Auth::SchemeConfig *nego = Auth::SchemeConfig::Find("Negotiate");
        Auth::SchemeConfig *ntlm = Auth::SchemeConfig::Find("NTLM");
        if ((nego && nego->active()) || (ntlm && ntlm->active())) {
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: pipeline_prefetch breaks NTLM and Negotiate authentication. Forced pipeline_prefetch 0.");
            Config.pipeline_max_prefetch = 0;
        }
    }

    for (auto &authSchemes : Auth::TheConfig.schemeLists) {
        authSchemes.expand();
        if (authSchemes.authConfigs.empty()) {
            debugs(3, DBG_CRITICAL, "auth_schemes: at least one scheme name is required; got: " << authSchemes.rawSchemes);
            self_destruct();
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

    if (!strcmp(name, "log_access")) {
        self_destruct();
        return;
    }

    if (!strcmp(name, "log_icap")) {
        self_destruct();
        return;
    }

    if (!strcmp(name, "ignore_ims_on_miss")) {
        // the replacement directive cache_revalidate_on_miss has opposite meanings for ON/OFF value
        // than the 2.7 directive. We need to parse and invert the configured value.
        int temp = 0;
        parse_onoff(&temp);
        Config.onoff.cache_miss_revalidate = !temp;
    }

    if (!strncmp(name, "sslproxy_", 9)) {
        // the replacement directive tls_outgoing_options uses options instead of whole-line input
        SBuf tmp;
        if (!strcmp(name, "sslproxy_cafile"))
            tmp.append("cafile=");
        else if (!strcmp(name, "sslproxy_capath"))
            tmp.append("capath=");
        else if (!strcmp(name, "sslproxy_cipher"))
            tmp.append("cipher=");
        else if (!strcmp(name, "sslproxy_client_certificate"))
            tmp.append("cert=");
        else if (!strcmp(name, "sslproxy_client_key"))
            tmp.append("key=");
        else if (!strcmp(name, "sslproxy_flags"))
            tmp.append("flags=");
        else if (!strcmp(name, "sslproxy_options"))
            tmp.append("options=");
        else if (!strcmp(name, "sslproxy_version"))
            tmp.append("version=");
        else {
            debugs(3, DBG_CRITICAL, "ERROR: unknown directive: " << name);
            self_destruct();
            return;
        }

        // add the value as unquoted-string because the old values did not support whitespace
        const char *token = ConfigParser::NextQuotedOrToEol();
        tmp.append(token, strlen(token));
        Security::ProxyOutgoingConfig.parse(tmp.c_str());
    }
}

template <class MinimalUnit>
static const char *
TimeUnitToString()
{
    const auto minUnit = MinimalUnit(1);
    if(minUnit == std::chrono::nanoseconds(1))
        return T_NANOSECOND_STR;
    else if (minUnit == std::chrono::microseconds(1))
        return T_MICROSECOND_STR;
    else if (minUnit == std::chrono::milliseconds(1))
        return T_MILLISECOND_STR;
    else {
        assert(minUnit >= std::chrono::seconds(1));
        return T_SECOND_STR;
    }
}

/// Assigns 'ns' the number of nanoseconds corresponding to 'unitName'.
/// \param MinimalUnit is a chrono duration type specifying the minimal
/// allowed time unit.
/// \returns true if unitName is correct and its time unit is not less
/// than MinimalUnit.
template <class MinimalUnit>
static bool
parseTimeUnit(const char *unitName, std::chrono::nanoseconds &ns)
{
    if (!unitName)
        throw TexcHere("missing time unit");

    if (!strncasecmp(unitName, T_NANOSECOND_STR, strlen(T_NANOSECOND_STR)))
        ns = std::chrono::nanoseconds(1);
    else if (!strncasecmp(unitName, T_MICROSECOND_STR, strlen(T_MICROSECOND_STR)))
        ns = std::chrono::microseconds(1);
    else if (!strncasecmp(unitName, T_MILLISECOND_STR, strlen(T_MILLISECOND_STR)))
        ns = std::chrono::milliseconds(1);
    else if (!strncasecmp(unitName, T_SECOND_STR, strlen(T_SECOND_STR)))
        ns = std::chrono::seconds(1);
    else if (!strncasecmp(unitName, T_MINUTE_STR, strlen(T_MINUTE_STR)))
        ns = std::chrono::minutes(1);
    else if (!strncasecmp(unitName, T_HOUR_STR, strlen(T_HOUR_STR)))
        ns = std::chrono::hours(1);
    else if (!strncasecmp(unitName, T_DAY_STR, strlen(T_DAY_STR)))
        ns = std::chrono::hours(24);
    else if (!strncasecmp(unitName, T_WEEK_STR, strlen(T_WEEK_STR)))
        ns = std::chrono::hours(24 * 7);
    else if (!strncasecmp(unitName, T_FORTNIGHT_STR, strlen(T_FORTNIGHT_STR)))
        ns = std::chrono::hours(24 * 14);
    else if (!strncasecmp(unitName, T_MONTH_STR, strlen(T_MONTH_STR)))
        ns = std::chrono::hours(24 * 30);
    else if (!strncasecmp(unitName, T_YEAR_STR, strlen(T_YEAR_STR)))
        ns = std::chrono::hours(static_cast<std::chrono::hours::rep>(HoursPerYear));
    else if (!strncasecmp(unitName, T_DECADE_STR, strlen(T_DECADE_STR)))
        ns = std::chrono::hours(static_cast<std::chrono::hours::rep>(HoursPerYear * 10));
    else
        return false;

    if (ns < MinimalUnit(1)) {
        throw TexcHere(ToSBuf("time unit '", unitName, "' is too small to be used in this context, the minimal unit is ",
                              TimeUnitToString<MinimalUnit>()));
    }

    return true;
}

static std::chrono::nanoseconds
ToNanoSeconds(const double value, const std::chrono::nanoseconds &unit)
{
    if (value < 0.0)
        throw TexcHere("time must have a positive value");

    if (value > (static_cast<double>(std::chrono::nanoseconds::max().count()) / unit.count())) {
        const auto maxYears = std::chrono::duration_cast<std::chrono::hours>(std::chrono::nanoseconds::max()).count()/HoursPerYear;
        throw TexcHere(ToSBuf("time values cannot exceed ", maxYears, " years"));
    }

    return std::chrono::duration_cast<std::chrono::nanoseconds>(unit * value);
}

template <class TimeUnit>
static TimeUnit
FromNanoseconds(const std::chrono::nanoseconds &ns, const double parsedValue)
{
    const auto result = std::chrono::duration_cast<TimeUnit>(ns);
    if (!result.count()) {
        throw TexcHere(ToSBuf("time value '", parsedValue,
                              "' is too small to be used in this context, the minimal value is 1 ",
                              TimeUnitToString<TimeUnit>()));
    }
    return result;
}

/// Parses a time specification from the config file and
/// returns the time as a chrono duration object of 'TimeUnit' type.
template <class TimeUnit>
static TimeUnit
parseTimeLine()
{
    const auto valueToken = ConfigParser::NextToken();
    if (!valueToken)
        throw TexcHere("cannot read a time value");

    const auto parsedValue = xatof(valueToken);

    if (parsedValue == 0)
        return TimeUnit::zero();

    std::chrono::nanoseconds parsedUnitDuration;

    const auto token = ConfigParser::PeekAtToken();

    if (!parseTimeUnit<TimeUnit>(token, parsedUnitDuration))
        throw TexcHere(ToSBuf("unknown time unit '", token, "'"));

    (void)ConfigParser::NextToken();

    const auto nanoseconds = ToNanoSeconds(parsedValue, parsedUnitDuration);

    // validate precisions (time-units-small only)
    if (TimeUnit(1) <= std::chrono::microseconds(1)) {
        if (0 < nanoseconds.count() && nanoseconds.count() < 3) {
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), ConfigParser::CurrentLocation() << ": WARNING: " <<
                   "Squid time measurement precision is likely to be far worse than " <<
                   "the nanosecond-level precision implied by the configured value: " << parsedValue << ' ' << token);
        }
    }

    return FromNanoseconds<TimeUnit>(nanoseconds, parsedValue);
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

    if ((token = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }

    if (strcmp(token, "none") == 0 || strcmp(token, "-1") == 0) {
        *bptr = -1;
        return;
    }

    d = xatof(token);

    m = u;          /* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = ConfigParser::NextToken()) == nullptr)
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

    if ((token = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }

    if (strcmp(token, "none") == 0 || strcmp(token, "-1") == 0) {
        *bptr = static_cast<size_t>(-1);
        return;
    }

    d = xatof(token);

    m = u;          /* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = ConfigParser::NextToken()) == nullptr)
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

    if ((token = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }

    if (strcmp(token, "none") == 0 || token[0] == '-' /* -N */) {
        *bptr = -1;
        return;
    }

    d = xatof(token);

    m = u;          /* default to 'units' if none specified */

    if (0.0 == d)
        (void) 0;
    else if ((token = ConfigParser::NextToken()) == nullptr)
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

/**
 * Parse bytes from a string.
 * Similar to the parseBytesLine function but parses the string value instead of
 * the current token value.
 */
void
parseBytesOptionValue(size_t * bptr, const char *units, char const * value)
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
    number.assign(number_begin, number_end - number_begin);

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

static void
parse_SBufList(SBufList * list)
{
    while (char *token = ConfigParser::NextQuotedToken())
        list->push_back(SBuf(token));
}

// just dump a list, no directive name
static void
dump_SBufList(StoreEntry * entry, const SBufList &words)
{
    for (const auto &i : words) {
        entry->append(i.rawContent(), i.length());
        entry->append(" ",1);
    }
    entry->append("\n",1);
}

// dump a SBufList type directive with name
static void
dump_SBufList(StoreEntry * entry, const char *name, SBufList &list)
{
    if (!list.empty()) {
        entry->append(name, strlen(name));
        entry->append(" ", 1);
        dump_SBufList(entry, list);
    }
}

static void
free_SBufList(SBufList *list)
{
    if (list)
        list->clear();
}

static void
dump_acl(StoreEntry * entry, const char *name, ACL * ae)
{
    while (ae != nullptr) {
        debugs(3, 3, "dump_acl: " << name << " " << ae->name);
        storeAppendPrintf(entry, "%s %s %s ",
                          name,
                          ae->name,
                          ae->typeString());
        SBufList tail;
        tail.splice(tail.end(), ae->dumpOptions());
        tail.splice(tail.end(), ae->dump()); // ACL parameters
        dump_SBufList(entry, tail);
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
    // XXX: Should dump ACL names like "foo !bar" but dumps parsing context like
    // "(clientside_tos 0x11 line)".
    dump_SBufList(entry, head->dump());
}

void
dump_acl_access(StoreEntry * entry, const char *name, acl_access * head)
{
    if (head)
        dump_SBufList(entry, head->treeDump(name, &Acl::AllowOrDeny));
}

static void
parse_acl_access(acl_access ** head)
{
    aclParseAccessLine(cfg_directive, LegacyParser, head);
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
    storeAppendPrintf(entry, "%s %s\n", name, addr.toStr(buf,MAX_IPSTRLEN) );
}

static void
parse_address(Ip::Address *addr)
{
    char *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token,"any_addr"))
        addr->setAnyAddr();
    else if ( (!strcmp(token,"no_addr")) || (!strcmp(token,"full_mask")) )
        addr->setNoAddr();
    else if ( (*addr = token) ) // try parse numeric/IPA
        (void) 0;
    else if (addr->GetHostByName(token)) // do not use ipcache
        (void) 0;
    else { // not an IP and not a hostname
        debugs(3, DBG_CRITICAL, "FATAL: invalid IP address or domain name '" << token << "'");
        self_destruct();
    }
}

static void
free_address(Ip::Address *addr)
{
    addr->setEmpty();
}

static void
dump_acl_address(StoreEntry * entry, const char *name, Acl::Address * head)
{
    char buf[MAX_IPSTRLEN];

    for (Acl::Address *l = head; l; l = l->next) {
        if (!l->addr.isAnyAddr())
            storeAppendPrintf(entry, "%s %s", name, l->addr.toStr(buf,MAX_IPSTRLEN));
        else
            storeAppendPrintf(entry, "%s autoselect", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
parse_acl_address(Acl::Address ** head)
{
    Acl::Address *l = new Acl::Address;
    parse_address(&l->addr);
    aclParseAclList(LegacyParser, &l->aclList, l->addr);

    Acl::Address **tail = head;
    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_address(Acl::Address ** head)
{
    delete *head;
    *head = nullptr;
}

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
parse_acl_tos(acl_tos ** head)
{
    unsigned int tos;           /* Initially uint for strtoui. Casted to tos_t before return */
    char *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    if (!xstrtoui(token, nullptr, &tos, 0, std::numeric_limits<tos_t>::max())) {
        self_destruct();
        return;
    }

    const unsigned int chTos = tos & 0xFC;
    if (chTos != tos) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Tos value '" << tos << "' adjusted to '" << chTos << "'");
        tos = chTos;
    }

    acl_tos *l = new acl_tos;

    l->tos = (tos_t)tos;

    aclParseAclList(LegacyParser, &l->aclList, token);

    acl_tos **tail = head;  /* sane name below */
    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_tos(acl_tos ** head)
{
    delete *head;
    *head = nullptr;
}

#if SO_MARK && USE_LIBCAP

static void
dump_acl_nfmark(StoreEntry * entry, const char *name, acl_nfmark * head)
{
    for (acl_nfmark *l = head; l; l = l->next) {
        storeAppendPrintf(entry, "%s %s", name, ToSBuf(l->markConfig).c_str());

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
parse_acl_nfmark(acl_nfmark ** head)
{
    SBuf token(ConfigParser::NextToken());
    const auto mc = Ip::NfMarkConfig::Parse(token);

    // Packet marking directives should not allow to use masks.
    const auto pkt_dirs = {"mark_client_packet", "clientside_mark", "tcp_outgoing_mark"};
    if (mc.hasMask() && std::find(pkt_dirs.begin(), pkt_dirs.end(), cfg_directive) != pkt_dirs.end())
        throw TexcHere(ToSBuf("'", cfg_directive, "' does not support masked marks"));

    acl_nfmark *l = new acl_nfmark;
    l->markConfig = mc;

    aclParseAclList(LegacyParser, &l->aclList, token.c_str());

    acl_nfmark **tail = head;   /* sane name below */
    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_nfmark(acl_nfmark ** head)
{
    delete *head;
    *head = nullptr;
}
#endif /* SO_MARK */

static void
dump_acl_b_size_t(StoreEntry * entry, const char *name, AclSizeLimit * head)
{
    for (AclSizeLimit *l = head; l; l = l->next) {
        if (l->size != -1)
            storeAppendPrintf(entry, "%s %d %s\n", name, (int) l->size, B_BYTES_STR);
        else
            storeAppendPrintf(entry, "%s none", name);

        dump_acl_list(entry, l->aclList);

        storeAppendPrintf(entry, "\n");
    }
}

static void
parse_acl_b_size_t(AclSizeLimit ** head)
{
    AclSizeLimit *l = new AclSizeLimit;

    parse_b_int64_t(&l->size);

    aclParseAclList(LegacyParser, &l->aclList, l->size);

    AclSizeLimit **tail = head; /* sane name below */
    while (*tail)
        tail = &(*tail)->next;

    *tail = l;
}

static void
free_acl_b_size_t(AclSizeLimit ** head)
{
    delete *head;
    *head = nullptr;
}

#if USE_DELAY_POOLS

#include "DelayConfig.h"
#include "DelayPools.h"
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
    cfg->freePools();
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
    char *t = nullptr;

    if ((t = ConfigParser::NextToken()) == nullptr) {
        debugs(3, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, DBG_CRITICAL, "ERROR: parse_http_header_access: missing header name.");
        return;
    }

    if (!*pm)
        *pm = new HeaderManglers;
    HeaderManglers *manglers = *pm;
    headerMangler *mangler = manglers->track(t);
    assert(mangler);

    std::string directive = "http_header_access ";
    directive += t;
    aclParseAccessLine(directive.c_str(), LegacyParser, &mangler->access_list);
}

static void
free_HeaderManglers(HeaderManglers **pm)
{
    // we delete the entire http_header_* mangler configuration at once
    if (const HeaderManglers *manglers = *pm) {
        delete manglers;
        *pm = nullptr;
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
    char *t = nullptr;

    if ((t = ConfigParser::NextToken()) == nullptr) {
        debugs(3, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(3, DBG_CRITICAL, "ERROR: parse_http_header_replace: missing header name.");
        return;
    }

    const char *value = ConfigParser::NextQuotedOrToEol();

    if (!*pm)
        *pm = new HeaderManglers;
    HeaderManglers *manglers = *pm;
    manglers->setReplacement(t, value);
}

#endif

static void
dump_cachedir(StoreEntry * entry, const char *name, const Store::DiskConfig &swap)
{
    Store::Disks::Dump(swap, *entry, name);
}

static int
check_null_string(char *s)
{
    return s == nullptr;
}

#if USE_AUTH
static void
parse_authparam(Auth::ConfigVector * config)
{
    char *type_str = ConfigParser::NextToken();
    if (!type_str) {
        self_destruct();
        return;
    }

    char *param_str = ConfigParser::NextToken();
    if (!param_str) {
        self_destruct();
        return;
    }

    /* find a configuration for the scheme in the currently parsed configs... */
    Auth::SchemeConfig *schemeCfg = Auth::SchemeConfig::Find(type_str);

    if (schemeCfg == nullptr) {
        /* Create a configuration based on the scheme info */
        Auth::Scheme::Pointer theScheme = Auth::Scheme::Find(type_str);

        if (theScheme == nullptr) {
            debugs(3, DBG_CRITICAL, "ERROR: Failure while parsing Config File: Unknown authentication scheme '" << type_str << "'.");
            self_destruct();
            return;
        }

        config->push_back(theScheme->createConfig());
        schemeCfg = Auth::SchemeConfig::Find(type_str);
        if (schemeCfg == nullptr) {
            debugs(3, DBG_CRITICAL, "Parsing Config File: Corruption configuring authentication scheme '" << type_str << "'.");
            self_destruct();
            return;
        }
    }

    schemeCfg->parse(schemeCfg, config->size(), param_str);
}

static void
free_authparam(Auth::ConfigVector * cfg)
{
    /* Wipe the Auth globals and Detach/Destruct component config + state. */
    cfg->clear();

    /* on reconfigure initialize new auth schemes for the new config. */
    if (reconfiguring) {
        Auth::Init();
    }
}

static void
dump_authparam(StoreEntry * entry, const char *name, Auth::ConfigVector cfg)
{
    for (auto *scheme : cfg)
        scheme->dump(entry, name, scheme);
}

static void
parse_AuthSchemes(acl_access **authSchemes)
{
    const char *tok = ConfigParser::NextQuotedToken();
    if (!tok) {
        debugs(29, DBG_CRITICAL, "FATAL: auth_schemes missing the parameter");
        self_destruct();
        return;
    }
    Auth::TheConfig.schemeLists.emplace_back(tok, ConfigParser::LastTokenWasQuoted());
    const auto action = Acl::Answer(ACCESS_ALLOWED, Auth::TheConfig.schemeLists.size() - 1);
    ParseAclWithAction(authSchemes, action, "auth_schemes");
}

static void
free_AuthSchemes(acl_access **authSchemes)
{
    Auth::TheConfig.schemeLists.clear();
    free_acl_access(authSchemes);
}

static void
dump_AuthSchemes(StoreEntry *entry, const char *name, acl_access *authSchemes)
{
    if (authSchemes)
        dump_SBufList(entry, authSchemes->treeDump(name, [](const Acl::Answer &action) {
        return Auth::TheConfig.schemeLists.at(action.kind).rawSchemes;
    }));
}

#endif /* USE_AUTH */

static void
ParseAclWithAction(acl_access **access, const Acl::Answer &action, const char *desc, ACL *acl)
{
    assert(access);
    SBuf name;
    if (!*access) {
        *access = new Acl::Tree;
        name.Printf("(%s rules)", desc);
        (*access)->context(name.c_str(), config_input_line);
    }
    Acl::AndNode *rule = new Acl::AndNode;
    name.Printf("(%s rule)", desc);
    rule->context(name.c_str(), config_input_line);
    if (acl)
        rule->add(acl);
    else
        rule->lineParse();
    (*access)->add(rule, action);
}

static void
parse_cachedir(Store::DiskConfig *swap)
{
    assert(swap);
    Store::Disks::Parse(*swap);
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
    NeighborTypeDomainList *t;
    LOCAL_ARRAY(char, xname, 128);

    while (p != nullptr) {
        storeAppendPrintf(entry, "%s %s %s %d %d name=%s",
                          name,
                          p->host,
                          neighborTypeStr(p),
                          p->http_port,
                          p->icp.port,
                          p->name);
        dump_peer_options(entry, p);

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
 \param proto   'tcp' or 'udp' for protocol
 \returns       Port the named service is supposed to be listening on.
 */
static unsigned short
GetService(const char *proto)
{
    struct servent *port = nullptr;
    /** Parses a port number or service name from the squid.conf */
    char *token = ConfigParser::NextToken();
    if (token == nullptr) {
        self_destruct();
        return 0; /* NEVER REACHED */
    }
    /** Returns either the service port number from /etc/services */
    if ( !isUnsignedNumeric(token, strlen(token)) )
        port = getservbyname(token, proto);
    if (port != nullptr) {
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
    char *host_str = ConfigParser::NextToken();
    if (!host_str) {
        self_destruct();
        return;
    }

    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

    const auto p = new CachePeer(host_str);

    p->type = parseNeighborType(token);

    if (p->type == PEER_MULTICAST) {
        p->options.no_digest = true;
        p->options.no_netdb_exchange = true;
    }

    p->http_port = GetTcpService();

    if (!p->http_port) {
        delete p;
        self_destruct();
        return;
    }

    p->icp.port = GetUdpService();

    while ((token = ConfigParser::NextToken())) {
        if (!strcmp(token, "proxy-only")) {
            p->options.proxy_only = true;
        } else if (!strcmp(token, "no-query")) {
            p->options.no_query = true;
        } else if (!strcmp(token, "background-ping")) {
            p->options.background_ping = true;
        } else if (!strcmp(token, "no-digest")) {
            p->options.no_digest = true;
        } else if (!strcmp(token, "no-tproxy")) {
            p->options.no_tproxy = true;
        } else if (!strcmp(token, "multicast-responder")) {
            p->options.mcast_responder = true;
#if PEER_MULTICAST_SIBLINGS
        } else if (!strcmp(token, "multicast-siblings")) {
            p->options.mcast_siblings = true;
#endif
        } else if (!strncmp(token, "weight=", 7)) {
            p->weight = xatoi(token + 7);
        } else if (!strncmp(token, "basetime=", 9)) {
            p->basetime = xatoi(token + 9);
        } else if (!strcmp(token, "closest-only")) {
            p->options.closest_only = true;
        } else if (!strncmp(token, "ttl=", 4)) {
            p->mcast.ttl = xatoi(token + 4);

            if (p->mcast.ttl < 0)
                p->mcast.ttl = 0;

            if (p->mcast.ttl > 128)
                p->mcast.ttl = 128;
        } else if (!strcmp(token, "default")) {
            p->options.default_parent = true;
        } else if (!strcmp(token, "round-robin")) {
            p->options.roundrobin = true;
        } else if (!strcmp(token, "weighted-round-robin")) {
            p->options.weighted_roundrobin = true;
#if USE_HTCP
        } else if (!strcmp(token, "htcp")) {
            p->options.htcp = true;
        } else if (!strncmp(token, "htcp=", 5) || !strncmp(token, "htcp-", 5)) {
            /* Note: The htcp- form is deprecated, replaced by htcp= */
            p->options.htcp = true;
            char *tmp = xstrdup(token+5);
            char *mode, *nextmode;
            for (mode = nextmode = tmp; mode; mode = nextmode) {
                nextmode = strchr(mode, ',');
                if (nextmode) {
                    *nextmode = '\0';
                    ++nextmode;
                }
                if (!strcmp(mode, "no-clr")) {
                    if (p->options.htcp_only_clr)
                        fatalf("parse_peer: can't set htcp-no-clr and htcp-only-clr simultaneously");
                    p->options.htcp_no_clr = true;
                } else if (!strcmp(mode, "no-purge-clr")) {
                    p->options.htcp_no_purge_clr = true;
                } else if (!strcmp(mode, "only-clr")) {
                    if (p->options.htcp_no_clr)
                        fatalf("parse_peer: can't set htcp no-clr and only-clr simultaneously");
                    p->options.htcp_only_clr = true;
                } else if (!strcmp(mode, "forward-clr")) {
                    p->options.htcp_forward_clr = true;
                } else if (!strcmp(mode, "oldsquid")) {
                    p->options.htcp_oldsquid = true;
                } else {
                    fatalf("invalid HTCP mode '%s'", mode);
                }
            }
            safe_free(tmp);
#endif
        } else if (!strcmp(token, "no-netdb-exchange")) {
            p->options.no_netdb_exchange = true;

        } else if (!strcmp(token, "carp")) {
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent carp cache_peer ", *p), Here());

            p->options.carp = true;
        } else if (!strncmp(token, "carp-key=", 9)) {
            if (p->options.carp != true)
                throw TextException(ToSBuf("carp-key specified on non-carp cache_peer ", *p), Here());
            p->options.carp_key.set = true;
            char *nextkey=token+strlen("carp-key="), *key=nextkey;
            for (; key; key = nextkey) {
                nextkey=strchr(key,',');
                if (nextkey) ++nextkey; // skip the comma, any
                if (0==strncmp(key,"scheme",6)) {
                    p->options.carp_key.scheme = true;
                } else if (0==strncmp(key,"host",4)) {
                    p->options.carp_key.host = true;
                } else if (0==strncmp(key,"port",4)) {
                    p->options.carp_key.port = true;
                } else if (0==strncmp(key,"path",4)) {
                    p->options.carp_key.path = true;
                } else if (0==strncmp(key,"params",6)) {
                    p->options.carp_key.params = true;
                } else {
                    fatalf("invalid carp-key '%s'",key);
                }
            }
        } else if (!strcmp(token, "userhash")) {
#if USE_AUTH
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent userhash cache_peer ", *p), Here());

            p->options.userhash = true;
#else
            throw TextException(ToSBuf("missing authentication support; required for userhash cache_peer ", *p), Here());
#endif
        } else if (!strcmp(token, "sourcehash")) {
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent sourcehash cache_peer ", *p), Here());

            p->options.sourcehash = true;

        } else if (!strcmp(token, "no-delay")) {
#if USE_DELAY_POOLS
            p->options.no_delay = true;
#else
            debugs(0, DBG_CRITICAL, "WARNING: cache_peer option 'no-delay' requires --enable-delay-pools");
#endif
        } else if (!strncmp(token, "login=", 6)) {
            p->login = xstrdup(token + 6);
            rfc1738_unescape(p->login);
        } else if (!strcmp(token, "auth-no-keytab")) {
            p->options.auth_no_keytab = 1;
        } else if (!strncmp(token, "connect-timeout=", 16)) {
            p->connect_timeout_raw = xatoi(token + 16);
        } else if (!strncmp(token, "connect-fail-limit=", 19)) {
            p->connect_fail_limit = xatoi(token + 19);
#if USE_CACHE_DIGESTS
        } else if (!strncmp(token, "digest-url=", 11)) {
            p->digest_url = xstrdup(token + 11);
#endif

        } else if (!strcmp(token, "allow-miss")) {
            p->options.allow_miss = true;
        } else if (!strncmp(token, "max-conn=", 9)) {
            p->max_conn = xatoi(token + 9);
        } else if (!strncmp(token, "standby=", 8)) {
            p->standby.limit = xatoi(token + 8);
        } else if (!strcmp(token, "originserver")) {
            p->options.originserver = true;
        } else if (!strncmp(token, "name=", 5)) {
            p->rename(token + 5);
        } else if (!strncmp(token, "forceddomain=", 13)) {
            safe_free(p->domain);
            if (token[13])
                p->domain = xstrdup(token + 13);

        } else if (strncmp(token, "ssl", 3) == 0) {
#if !USE_OPENSSL
            debugs(0, DBG_CRITICAL, "WARNING: cache_peer option '" << token << "' requires --with-openssl");
#else
            p->secure.parse(token+3);
#endif
        } else if (strncmp(token, "tls-", 4) == 0) {
            p->secure.parse(token+4);
        } else if (strncmp(token, "tls", 3) == 0) {
            p->secure.parse(token+3);
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
        } else if (token[0] == '#') {
            // start of a text comment. stop reading this line.
            break;
        } else {
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Ignoring unknown cache_peer option '" << token << "'");
        }
    }

    if (findCachePeerByName(p->name))
        throw TextException(ToSBuf("cache_peer ", *p, " specified twice"), Here());

    if (p->max_conn > 0 && p->max_conn < p->standby.limit)
        throw TextException(ToSBuf("cache_peer ", *p, " max-conn=", p->max_conn,
                                   " is lower than its standby=", p->standby.limit), Here());

    if (p->weight < 1)
        p->weight = 1;

    if (p->connect_fail_limit < 1)
        p->connect_fail_limit = 10;

#if USE_CACHE_DIGESTS
    if (!p->options.no_digest)
        peerDigestCreate(p);
#endif

    if (p->secure.encryptTransport)
        p->secure.parseOptions();

    p->index =  ++Config.npeers;

    while (*head != nullptr)
        head = &(*head)->next;

    *head = p;

    peerClearRRStart();
}

static void
free_peer(CachePeer ** P)
{
    delete *P;
    *P = nullptr;
    Config.npeers = 0;
}

static void
dump_cachemgrpasswd(StoreEntry * entry, const char *name, Mgr::ActionPasswordList * list)
{
    while (list) {
        if (strcmp(list->passwd, "none") && strcmp(list->passwd, "disable"))
            storeAppendPrintf(entry, "%s XXXXXXXXXX", name);
        else
            storeAppendPrintf(entry, "%s %s", name, list->passwd);

        for (auto w : list->actions)
            entry->appendf(" " SQUIDSBUFPH, SQUIDSBUFPRINT(w));

        storeAppendPrintf(entry, "\n");
        list = list->next;
    }
}

static void
parse_cachemgrpasswd(Mgr::ActionPasswordList ** head)
{
    char *passwd = nullptr;
    parse_string(&passwd);

    Mgr::ActionPasswordList *p = new Mgr::ActionPasswordList;
    p->passwd = passwd;

    while (char *token = ConfigParser::NextQuotedToken())
        p->actions.push_back(SBuf(token));

    Mgr::ActionPasswordList **P;
    for (P = head; *P; P = &(*P)->next) {
        /*
         * See if any of the actions from this line already have a
         * password from previous lines.  The password checking
         * routines in cache_manager.c take the the password from
         * the first Mgr::ActionPasswordList that contains the
         * requested action.  Thus, we should warn users who might
         * think they can have two passwords for the same action.
         */
        for (const auto &w : (*P)->actions) {
            for (const auto &u : p->actions) {
                if (w != u)
                    continue;

                debugs(0, DBG_PARSE_NOTE(1), "ERROR: action '" << u << "' (line " << config_lineno << ") already has a password");
            }
        }
    }

    *P = p;
}

static void
free_cachemgrpasswd(Mgr::ActionPasswordList ** head)
{
    delete *head;
    *head = nullptr;
}

static void
dump_denyinfo(StoreEntry * entry, const char *name, AclDenyInfoList * var)
{
    while (var != nullptr) {
        storeAppendPrintf(entry, "%s %s", name, var->err_page_name);

        for (const auto &aclName: var->acl_list)
            storeAppendPrintf(entry, " " SQUIDSBUFPH, SQUIDSBUFPRINT(aclName));

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
    delete *list;
    *list = nullptr;
}

static void
parse_peer_access(void)
{
    auto &p = LegacyParser.cachePeer("cache_peer_access peer-name");
    std::string directive = "peer_access ";
    directive += p.name;
    aclParseAccessLine(directive.c_str(), LegacyParser, &p.access);
}

static void
parse_hostdomaintype(void)
{
    auto &p = LegacyParser.cachePeer("neighbor_type_domain peer-name");

    char *type = ConfigParser::NextToken();
    if (!type) {
        self_destruct();
        return;
    }

    char *domain = nullptr;
    while ((domain = ConfigParser::NextToken())) {
        auto *l = static_cast<NeighborTypeDomainList *>(xcalloc(1, sizeof(NeighborTypeDomainList)));
        l->type = parseNeighborType(type);
        l->domain = xstrdup(domain);

        NeighborTypeDomainList **L = nullptr;
        for (L = &p.typelist; *L; L = &((*L)->next));
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
dump_int64_t(StoreEntry * entry, const char *name, int64_t var)
{
    storeAppendPrintf(entry, "%s %" PRId64 "\n", name, var);
}

static void
parse_int64_t(int64_t *var)
{
    int64_t i;
    i = GetInteger64();
    *var = i;
}

static void
free_int64_t(int64_t *var)
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
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token, "on")) {
        *var = 1;
    } else if (!strcmp(token, "enable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'enable' is deprecated. Please update to use 'on'.");
        *var = 1;
    } else if (!strcmp(token, "off")) {
        *var = 0;
    } else if (!strcmp(token, "disable")) {
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
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token, "on")) {
        *var = 1;
    } else if (!strcmp(token, "enable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'enable' is deprecated. Please update to use value 'on'.");
        *var = 1;
    } else if (!strcmp(token, "warn")) {
        *var = -1;
    } else if (!strcmp(token, "off")) {
        *var = 0;
    } else if (!strcmp(token, "disable")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'disable' is deprecated. Please update to use value 'off'.");
        *var = 0;
    } else {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Invalid option: Tristate options can only be 'on', 'off', or 'warn'.");
        self_destruct();
    }
}

#define free_tristate free_int

static void
parse_pipelinePrefetch(int *var)
{
    char *token = ConfigParser::PeekAtToken();
    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token, "on")) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: 'pipeline_prefetch on' is deprecated. Please update to use 1 (or a higher number).");
        *var = 1;
        //pop the token
        (void)ConfigParser::NextToken();
    } else if (!strcmp(token, "off")) {
        debugs(0, DBG_PARSE_NOTE(2), "WARNING: 'pipeline_prefetch off' is deprecated. Please update to use '0'.");
        *var = 0;
        //pop the token
        (void)ConfigParser::NextToken();
    } else
        parse_int(var);
}

#define free_pipelinePrefetch free_int
#define dump_pipelinePrefetch dump_int

static void
dump_refreshpattern(StoreEntry * entry, const char *name, RefreshPattern * head)
{
    while (head != nullptr) {
        PackableStream os(*entry);
        os << name << ' ';
        head->printHead(os);

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

        if (head->flags.ignore_private)
            storeAppendPrintf(entry, " ignore-private");
#endif

        storeAppendPrintf(entry, "\n");

        head = head->next;
    }
}

static void
parse_refreshpattern(RefreshPattern ** head)
{
    char *token;
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
    int ignore_private = 0;
#endif

    int i;
    RefreshPattern *t;

    auto regex = LegacyParser.regex("refresh_pattern regex");

    i = GetInteger();       /* token: min */

    /* catch negative and insanely huge values close to 32-bit wrap */
    if (i < 0) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern minimum age negative. Cropped back to zero.");
        i = 0;
    }
    if (i > 60*24*365) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern minimum age too high. Cropped back to 1 year.");
        i = 60*24*365;
    }

    min = (time_t) (i * 60);    /* convert minutes to seconds */

    pct = GetPercentage(false);    /* token: pct . with no limit on size */

    i = GetInteger();       /* token: max */

    /* catch negative and insanely huge values close to 32-bit wrap */
    if (i < 0) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern maximum age negative. Cropped back to zero.");
        i = 0;
    }
    if (i > 60*24*365) {
        debugs(3, DBG_IMPORTANT, "WARNING: refresh_pattern maximum age too high. Cropped back to 1 year.");
        i = 60*24*365;
    }

    max = (time_t) (i * 60);    /* convert minutes to seconds */

    /* Options */
    while ((token = ConfigParser::NextToken()) != nullptr) {
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
        else if (!strcmp(token, "ignore-private"))
            ignore_private = 1;
        else if (!strcmp(token, "reload-into-ims")) {
            reload_into_ims = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
        } else if (!strcmp(token, "ignore-reload")) {
            ignore_reload = 1;
            refresh_nocache_hack = 1;
            /* tell client_side.c that this is used */
#endif

        } else if (!strcmp(token, "ignore-no-cache") ||
                   !strcmp(token, "ignore-must-revalidate") ||
                   !strcmp(token, "ignore-auth")
                  ) {
            debugs(22, DBG_PARSE_NOTE(2), "UPGRADE: refresh_pattern option '" << token << "' is obsolete. Remove it.");
        } else
            debugs(22, DBG_CRITICAL, "ERROR: Unknown refresh_pattern option: " << token);
    }

    pct = pct < 0.0 ? 0.0 : pct;
    max = max < 0 ? 0 : max;
    t = new RefreshPattern(std::move(regex));
    t->min = min;
    t->pct = pct;
    t->max = max;

    if (refresh_ims)
        t->flags.refresh_ims = true;

    if (store_stale)
        t->flags.store_stale = true;

    t->max_stale = max_stale;

#if USE_HTTP_VIOLATIONS

    if (override_expire)
        t->flags.override_expire = true;

    if (override_lastmod)
        t->flags.override_lastmod = true;

    if (reload_into_ims)
        t->flags.reload_into_ims = true;

    if (ignore_reload)
        t->flags.ignore_reload = true;

    if (ignore_no_store)
        t->flags.ignore_no_store = true;

    if (ignore_private)
        t->flags.ignore_private = true;
#endif

    t->next = nullptr;

    while (*head)
        head = &(*head)->next;

    *head = t;
}

static void
free_refreshpattern(RefreshPattern ** head)
{
    delete *head;
    *head = nullptr;

#if USE_HTTP_VIOLATIONS
    refresh_nocache_hack = 0;

#endif
}

static void
dump_string(StoreEntry * entry, const char *name, char *var)
{
    if (var != nullptr)
        storeAppendPrintf(entry, "%s %s\n", name, var);
}

static void
parse_string(char **var)
{
    safe_free(*var);

    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

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
    if (!var) {
        self_destruct();
        return;
    }

    unsigned char *token = (unsigned char *) ConfigParser::NextQuotedOrToEol();
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
parse_TokenOrQuotedString(char **var)
{
    safe_free(*var);

    char *token = ConfigParser::NextQuotedToken();
    if (!token) {
        self_destruct();
        return;
    }

    *var = xstrdup(token);
}

#define dump_TokenOrQuotedString dump_string
#define free_TokenOrQuotedString free_string

static void
dump_time_t(StoreEntry * entry, const char *name, time_t var)
{
    PackableStream os(*entry);
    os << name << ' ' << var << " seconds\n";
}

void
parse_time_t(time_t * var)
{
    const auto maxTime = std::numeric_limits<time_t>::max();
    const auto seconds = parseTimeLine<std::chrono::seconds>();
    if (maxTime < seconds.count())
        throw TexcHere(ToSBuf("directive supports time values up to ", maxTime, " but is given ", seconds.count(), " seconds"));
    *var = static_cast<time_t>(seconds.count());
}

static void
free_time_t(time_t * var)
{
    *var = 0;
}

static void
dump_time_msec(StoreEntry * entry, const char *name, time_msec_t var)
{
    PackableStream os(*entry);
    if (var % 1000)
        os << name << ' ' << var << " milliseconds\n";
    else
        os << name << ' ' << (var/1000) << " seconds\n";
}

static void
parse_time_msec(time_msec_t *var)
{
    *var = parseTimeLine<std::chrono::milliseconds>().count();
}

static void
free_time_msec(time_msec_t * var)
{
    *var = 0;
}

static void
dump_time_nanoseconds(StoreEntry *entry, const char *name, const std::chrono::nanoseconds &var)
{
    // std::chrono::nanoseconds::rep is unknown a priori so we cast to (and print) the largest supported integer
    storeAppendPrintf(entry, "%s %jd nanoseconds\n", name, static_cast<intmax_t>(var.count()));
}

static void
parse_time_nanoseconds(std::chrono::nanoseconds *var)
{
    *var = parseTimeLine<std::chrono::nanoseconds>();
}

static void
free_time_nanoseconds(std::chrono::nanoseconds *var)
{
    *var = std::chrono::nanoseconds::zero();
}

static void
dump_b_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}

static void
dump_b_ssize_t(StoreEntry * entry, const char *name, ssize_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}

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

static void
parse_b_size_t(size_t * var)
{
    parseBytesLine(var, B_BYTES_STR);
}

static void
parse_b_ssize_t(ssize_t * var)
{
    parseBytesLineSigned(var, B_BYTES_STR);
}

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
free_ssize_t(ssize_t * var)
{
    *var = 0;
}

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
    while (list != nullptr) {
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
    while ((token = ConfigParser::NextQuotedToken()))
        wordlistAdd(list, token);
}

static int
check_null_acl_access(acl_access * a)
{
    return a == nullptr;
}

#define free_wordlist wordlistDestroy

#define free_uri_whitespace free_int

static void
parse_uri_whitespace(int *var)
{
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

    if (!strcmp(token, "strip"))
        *var = URI_WHITESPACE_STRIP;
    else if (!strcmp(token, "deny"))
        *var = URI_WHITESPACE_DENY;
    else if (!strcmp(token, "allow"))
        *var = URI_WHITESPACE_ALLOW;
    else if (!strcmp(token, "encode"))
        *var = URI_WHITESPACE_ENCODE;
    else if (!strcmp(token, "chop"))
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

    *settings = nullptr;
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
{}

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
free_memcachemode(SquidConfig *)
{}

static void
parse_memcachemode(SquidConfig *)
{
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

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
dump_memcachemode(StoreEntry * entry, const char *name, SquidConfig &)
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
    if (!strcmp(s, "parent"))
        return PEER_PARENT;

    if (!strcmp(s, "neighbor"))
        return PEER_SIBLING;

    if (!strcmp(s, "neighbour"))
        return PEER_SIBLING;

    if (!strcmp(s, "sibling"))
        return PEER_SIBLING;

    if (!strcmp(s, "multicast"))
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

    while ((token = ConfigParser::NextToken())) {
        if (GetHostWithPort(token, &ipa)) {

            while (*head)
                head = &(*head)->next;

            s = static_cast<Ip::Address_list *>(xcalloc(1, sizeof(*s)));
            s->s = ipa;

            *head = s;
        } else {
            self_destruct();
            return;
        }
    }
}

static void
dump_IpAddress_list(StoreEntry * e, const char *n, const Ip::Address_list * s)
{
    char ntoabuf[MAX_IPSTRLEN];

    while (s) {
        storeAppendPrintf(e, "%s %s\n",
                          n,
                          s->s.toStr(ntoabuf,MAX_IPSTRLEN));
        s = s->next;
    }
}

static void
free_IpAddress_list(Ip::Address_list ** head)
{
    if (*head) delete *head;
    *head = nullptr;
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
parsePortSpecification(const AnyP::PortCfgPointer &s, char *token)
{
    char *host = nullptr;
    unsigned short port = 0;
    char *t = nullptr;
    char *junk = nullptr;

    s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
    s->name = xstrdup(token);
    s->connection_auth_disabled = false;

    const SBuf &portType = AnyP::UriScheme(s->transport.protocol).image();

    if (*token == '[') {
        /* [ipv6]:port */
        host = token + 1;
        t = strchr(host, ']');
        if (!t) {
            debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: missing ']' on IPv6 address: " << token);
            self_destruct();
            return;
        }
        *t = '\0';
        ++t;
        if (*t != ':') {
            debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: missing Port in: " << token);
            self_destruct();
            return;
        }
        if (!Ip::EnableIpv6) {
            debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: IPv6 is not available.");
            self_destruct();
            return;
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
        debugs(3, 3, portType << "_port: found Listen on Port: " << port);
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: missing Port: " << token);
        self_destruct();
        return;
    }

    if (port == 0 && host != nullptr) {
        debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: Port cannot be 0: " << token);
        self_destruct();
        return;
    }

    if (nullptr == host) {
        s->s.setAnyAddr();
        s->s.port(port);
        if (!Ip::EnableIpv6)
            s->s.setIPv4();
        debugs(3, 3, portType << "_port: found Listen on wildcard address: *:" << s->s.port());
    } else if ( (s->s = host) ) { /* check/parse numeric IPA */
        s->s.port(port);
        if (!Ip::EnableIpv6)
            s->s.setIPv4();
        debugs(3, 3, portType << "_port: Listen on Host/IP: " << host << " --> " << s->s);
    } else if ( s->s.GetHostByName(host) ) { /* check/parse for FQDN */
        /* do not use ipcache */
        s->defaultsite = xstrdup(host);
        s->s.port(port);
        if (!Ip::EnableIpv6)
            s->s.setIPv4();
        debugs(3, 3, portType << "_port: found Listen as Host " << s->defaultsite << " on IP: " << s->s);
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: " << portType << "_port: failed to resolve Host/IP: " << host);
        self_destruct();
    }
}

/// parses the protocol= option of the *_port directive, returning parsed value
/// unsupported option values result in a fatal error message
/// upper case values required; caller may convert for backward compatibility
static AnyP::ProtocolVersion
parsePortProtocol(const SBuf &value)
{
    // HTTP/1.0 not supported because we are version 1.1 which contains a superset of 1.0
    // and RFC 2616 requires us to upgrade 1.0 to 1.1
    if (value.cmp("HTTP") == 0 || value.cmp("HTTP/1.1") == 0)
        return Http::ProtocolVersion(1,1);

    if (value.cmp("HTTPS") == 0 || value.cmp("HTTPS/1.1") == 0)
        return AnyP::ProtocolVersion(AnyP::PROTO_HTTPS, 1,1);

    if (value.cmp("FTP") == 0)
        return Ftp::ProtocolVersion();

    fatalf("%s directive does not support protocol=" SQUIDSBUFPH "\n", cfg_directive, SQUIDSBUFPRINT(value));
    return AnyP::ProtocolVersion(); // not reached
}

static void
parse_port_option(AnyP::PortCfgPointer &s, char *token)
{
    /* modes first */

    if (strcmp(token, "accel") == 0) {
        if (s->flags.isIntercepted()) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": Accelerator mode requires its own port. It cannot be shared with other modes.");
            self_destruct();
            return;
        }
        s->flags.accelSurrogate = true;
        s->vhost = true;
    } else if (strcmp(token, "transparent") == 0 || strcmp(token, "intercept") == 0) {
        if (s->flags.accelSurrogate || s->flags.tproxyIntercept) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": Intercept mode requires its own interception port. It cannot be shared with other modes.");
            self_destruct();
            return;
        }
        s->flags.natIntercept = true;
        Ip::Interceptor.StartInterception();
        /* Log information regarding the port modes under interception. */
        debugs(3, DBG_IMPORTANT, "Starting Authentication on port " << s->s);
        debugs(3, DBG_IMPORTANT, "Disabling Authentication on port " << s->s << " (interception enabled)");
    } else if (strcmp(token, "tproxy") == 0) {
        if (s->flags.natIntercept || s->flags.accelSurrogate) {
            debugs(3,DBG_CRITICAL, "FATAL: " << cfg_directive << ": TPROXY option requires its own interception port. It cannot be shared with other modes.");
            self_destruct();
            return;
        }
        s->flags.tproxyIntercept = true;
        Ip::Interceptor.StartTransparency();
        /* Log information regarding the port modes under transparency. */
        debugs(3, DBG_IMPORTANT, "Disabling Authentication on port " << s->s << " (TPROXY enabled)");

        if (s->flags.proxySurrogate) {
            debugs(3, DBG_IMPORTANT, "Disabling TPROXY Spoofing on port " << s->s << " (require-proxy-header enabled)");
        }

        if (!Ip::Interceptor.ProbeForTproxy(s->s)) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": TPROXY support in the system does not work.");
            self_destruct();
            return;
        }

    } else if (strcmp(token, "require-proxy-header") == 0) {
        s->flags.proxySurrogate = true;
        if (s->flags.tproxyIntercept) {
            // receiving is still permitted, so we do not unset the TPROXY flag
            // spoofing access control override takes care of the spoof disable later
            debugs(3, DBG_IMPORTANT, "Disabling TPROXY Spoofing on port " << s->s << " (require-proxy-header enabled)");
        }

    } else if (strncmp(token, "defaultsite=", 12) == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": defaultsite option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
        safe_free(s->defaultsite);
        s->defaultsite = xstrdup(token + 12);
    } else if (strcmp(token, "vhost") == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "WARNING: " << cfg_directive << ": vhost option is deprecated. Use 'accel' mode flag instead.");
        }
        s->flags.accelSurrogate = true;
        s->vhost = true;
    } else if (strcmp(token, "no-vhost") == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_IMPORTANT, "ERROR: " << cfg_directive << ": no-vhost option requires Acceleration mode flag.");
        }
        s->vhost = false;
    } else if (strcmp(token, "vport") == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": vport option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
        s->vport = -1;
    } else if (strncmp(token, "vport=", 6) == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": vport option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
        s->vport = xatos(token + 6);
    } else if (strncmp(token, "protocol=", 9) == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": protocol option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
        s->transport = parsePortProtocol(ToUpper(SBuf(token + 9)));
    } else if (strcmp(token, "allow-direct") == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": allow-direct option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
        s->allow_direct = true;
    } else if (strcmp(token, "act-as-origin") == 0) {
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_IMPORTANT, "ERROR: " << cfg_directive << ": act-as-origin option requires Acceleration mode flag.");
        } else
            s->actAsOrigin = true;
    } else if (strcmp(token, "ignore-cc") == 0) {
#if !USE_HTTP_VIOLATIONS
        if (!s->flags.accelSurrogate) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": ignore-cc option requires Acceleration mode flag.");
            self_destruct();
            return;
        }
#endif
        s->ignore_cc = true;
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
        if (!strcmp(token + 23, "off"))
            s->disable_pmtu_discovery = DISABLE_PMTU_OFF;
        else if (!strcmp(token + 23, "transparent"))
            s->disable_pmtu_discovery = DISABLE_PMTU_TRANSPARENT;
        else if (!strcmp(token + 23, "always"))
            s->disable_pmtu_discovery = DISABLE_PMTU_ALWAYS;
        else {
            self_destruct();
            return;
        }
    } else if (strcmp(token, "ipv4") == 0) {
        if ( !s->s.setIPv4() ) {
            debugs(3, DBG_CRITICAL, "FATAL: " << cfg_directive << ": IPv6 addresses cannot be used as IPv4-Only. " << s->s );
            self_destruct();
            return;
        }
    } else if (strcmp(token, "tcpkeepalive") == 0) {
        s->tcp_keepalive.enabled = true;
    } else if (strncmp(token, "tcpkeepalive=", 13) == 0) {
        char *t = token + 13;
        s->tcp_keepalive.enabled = true;
        s->tcp_keepalive.idle = xatoui(t,',');
        t = strchr(t, ',');
        if (t) {
            ++t;
            s->tcp_keepalive.interval = xatoui(t,',');
            t = strchr(t, ',');
        }
        if (t) {
            ++t;
            s->tcp_keepalive.timeout = xatoui(t);
        }
#if USE_OPENSSL
    } else if (strcmp(token, "sslBump") == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: '" << token << "' is deprecated " <<
               "in " << cfg_directive << ". Use 'ssl-bump' instead.");
        s->flags.tunnelSslBumping = true;
    } else if (strcmp(token, "ssl-bump") == 0) {
        s->flags.tunnelSslBumping = true;
    } else if (strncmp(token, "cert=", 5) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "key=", 4) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "version=", 8) == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: '" << token << "' is deprecated " <<
               "in " << cfg_directive << ". Use 'options=' instead.");
        s->secure.parse(token);
    } else if (strncmp(token, "options=", 8) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "cipher=", 7) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "clientca=", 9) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "cafile=", 7) == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: '" << token << "' is deprecated " <<
               "in " << cfg_directive << ". Use 'tls-cafile=' instead.");
        s->secure.parse(token);
    } else if (strncmp(token, "capath=", 7) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "crlfile=", 8) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "dhparams=", 9) == 0) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: '" << token << "' is deprecated " <<
               "in " << cfg_directive << ". Use 'tls-dh=' instead.");
        s->secure.parse(token);
    } else if (strncmp(token, "sslflags=", 9) == 0) {
        // NP: deprecation warnings output by secure.parse() when relevant
        s->secure.parse(token+3);
    } else if (strncmp(token, "sslcontext=", 11) == 0) {
        // NP: deprecation warnings output by secure.parse() when relevant
        s->secure.parse(token+3);
    } else if (strncmp(token, "generate-host-certificates", 26) == 0) {
        s->secure.parse(token);
#endif
    } else if (strncmp(token, "dynamic_cert_mem_cache_size=", 28) == 0) {
        s->secure.parse(token);
    } else if (strncmp(token, "tls-", 4) == 0) {
        s->secure.parse(token+4);
    } else if (strcmp(token, "ftp-track-dirs") == 0) {
        s->ftp_track_dirs = true;
    } else if (strcmp(token, "worker-queues") == 0) {
#if !defined(SO_REUSEADDR)
#error missing system #include that #defines SO_* constants
#endif
#if !defined(SO_REUSEPORT)
        throw TexcHere(ToSBuf(cfg_directive, ' ', token, " option requires building Squid where SO_REUSEPORT is supported by the TCP stack"));
#endif
        s->workerQueues = true;
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: Unknown " << cfg_directive << " option '" << token << "'.");
        self_destruct();
    }
}

void
add_http_port(char *portspec)
{
    AnyP::PortCfgPointer s = new AnyP::PortCfg();
    s->transport = parsePortProtocol(SBuf("HTTP"));
    parsePortSpecification(s, portspec);
    // we may need to merge better if the above returns a list with clones
    assert(s->next == nullptr);
    s->next = HttpPortList;
    HttpPortList = s;
}

static void
parsePortCfg(AnyP::PortCfgPointer *head, const char *optionName)
{
    SBuf protoName;
    if (strcmp(optionName, "http_port") == 0 ||
            strcmp(optionName, "ascii_port") == 0)
        protoName = "HTTP";
    else if (strcmp(optionName, "https_port") == 0)
        protoName = "HTTPS";
    else if (strcmp(optionName, "ftp_port") == 0)
        protoName = "FTP";
    if (protoName.isEmpty()) {
        self_destruct();
        return;
    }

    char *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    AnyP::PortCfgPointer s = new AnyP::PortCfg();
    s->transport = parsePortProtocol(protoName); // default; protocol=... overwrites
    parsePortSpecification(s, token);

    /* parse options ... */
    while ((token = ConfigParser::NextToken())) {
        parse_port_option(s, token);
    }

    s->secure.syncCaFiles();

    if (s->transport.protocol == AnyP::PROTO_HTTPS) {
        s->secure.encryptTransport = true;
#if USE_OPENSSL
        /* ssl-bump on https_port configuration requires either tproxy or intercept, and vice versa */
        const bool hijacked = s->flags.isIntercepted();
        if (s->flags.tunnelSslBumping && !hijacked) {
            debugs(3, DBG_CRITICAL, "FATAL: ssl-bump on https_port requires tproxy/intercept which is missing.");
            self_destruct();
            return;
        }
        if (hijacked && !s->flags.tunnelSslBumping) {
            debugs(3, DBG_CRITICAL, "FATAL: tproxy/intercept on https_port requires ssl-bump which is missing.");
            self_destruct();
            return;
        }
#endif
        if (s->flags.proxySurrogate) {
            debugs(3,DBG_CRITICAL, "FATAL: https_port: require-proxy-header option is not supported on HTTPS ports.");
            self_destruct();
            return;
        }
    } else if (protoName.cmp("FTP") == 0) {
        /* ftp_port does not support ssl-bump */
        if (s->flags.tunnelSslBumping) {
            debugs(3, DBG_CRITICAL, "FATAL: ssl-bump is not supported for ftp_port.");
            self_destruct();
            return;
        }
        if (s->flags.proxySurrogate) {
            // Passive FTP data channel does not work without deep protocol inspection in the frontend.
            debugs(3,DBG_CRITICAL, "FATAL: require-proxy-header option is not supported on ftp_port.");
            self_destruct();
            return;
        }
    }

    if (s->secure.encryptTransport) {
        if (s->secure.certs.empty()) {
            debugs(3, DBG_CRITICAL, "FATAL: " << AnyP::UriScheme(s->transport.protocol) << "_port requires a cert= parameter");
            self_destruct();
            return;
        }
        s->secure.parseOptions();
    }

    // *_port line should now be fully valid so we can clone it if necessary
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && s->s.isAnyAddr()) {
        s->next = s->ipV4clone();
    }

    while (*head != nullptr)
        head = &((*head)->next);

    *head = s;
}

static void
dump_generic_port(StoreEntry * e, const char *n, const AnyP::PortCfgPointer &s)
{
    char buf[MAX_IPSTRLEN];

    storeAppendPrintf(e, "%s %s",
                      n,
                      s->s.toUrl(buf,MAX_IPSTRLEN));

    // MODES and specific sub-options.
    if (s->flags.natIntercept)
        storeAppendPrintf(e, " intercept");

    else if (s->flags.tproxyIntercept)
        storeAppendPrintf(e, " tproxy");

    else if (s->flags.proxySurrogate)
        storeAppendPrintf(e, " require-proxy-header");

    else if (s->flags.accelSurrogate) {
        storeAppendPrintf(e, " accel");

        if (s->vhost)
            storeAppendPrintf(e, " vhost");

        if (s->vport < 0)
            storeAppendPrintf(e, " vport");
        else if (s->vport > 0)
            storeAppendPrintf(e, " vport=%d", s->vport);

        if (s->defaultsite)
            storeAppendPrintf(e, " defaultsite=%s", s->defaultsite);

        // TODO: compare against prefix of 'n' instead of assuming http_port
        if (s->transport.protocol != AnyP::PROTO_HTTP)
            storeAppendPrintf(e, " protocol=%s", AnyP::ProtocolType_str[s->transport.protocol]);

        if (s->allow_direct)
            storeAppendPrintf(e, " allow-direct");

        if (s->ignore_cc)
            storeAppendPrintf(e, " ignore-cc");

    }

    // Generic independent options

    if (s->name)
        storeAppendPrintf(e, " name=%s", s->name);

#if USE_HTTP_VIOLATIONS
    if (!s->flags.accelSurrogate && s->ignore_cc)
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

    if (s->s.isAnyAddr() && !s->s.isIPv6())
        storeAppendPrintf(e, " ipv4");

    if (s->tcp_keepalive.enabled) {
        if (s->tcp_keepalive.idle || s->tcp_keepalive.interval || s->tcp_keepalive.timeout) {
            storeAppendPrintf(e, " tcpkeepalive=%d,%d,%d", s->tcp_keepalive.idle, s->tcp_keepalive.interval, s->tcp_keepalive.timeout);
        } else {
            storeAppendPrintf(e, " tcpkeepalive");
        }
    }

#if USE_OPENSSL
    if (s->flags.tunnelSslBumping)
        storeAppendPrintf(e, " ssl-bump");
#endif

    s->secure.dumpCfg(e, "tls-");
}

static void
dump_PortCfg(StoreEntry * e, const char *n, const AnyP::PortCfgPointer &s)
{
    for (AnyP::PortCfgPointer p = s; p != nullptr; p = p->next) {
        dump_generic_port(e, n, p);
        storeAppendPrintf(e, "\n");
    }
}

void
configFreeMemory(void)
{
    free_all();
    Dns::ResolveClientAddressesAsap = false;
    Config.ssl_client.sslContext.reset();
#if USE_OPENSSL
    Ssl::unloadSquidUntrusted();
#endif
}

void
requirePathnameExists(const char *name, const char *path)
{

    struct stat sb;
    char pathbuf[BUFSIZ];
    assert(path != nullptr);

    if (Config.chroot_dir && (geteuid() == 0)) {
        snprintf(pathbuf, BUFSIZ, "%s/%s", Config.chroot_dir, path);
        path = pathbuf;
    }

    if (stat(path, &sb) < 0) {
        int xerrno = errno;
        debugs(0, DBG_CRITICAL, (opt_parse_cfg_only?"FATAL: ":"ERROR: ") << name << " " << path << ": " << xstrerr(xerrno));
        // keep going to find more issues if we are only checking the config file with "-k parse"
        if (opt_parse_cfg_only)
            return;
        // this is fatal if it is found during startup or reconfigure
        if (opt_send_signal == -1 || opt_send_signal == SIGHUP)
            fatalf("%s %s: %s", name, path, xstrerr(xerrno));
    }
}

#include "AccessLogEntry.h"

/**
 * We support several access_log configuration styles:
 *
 * #1: Deprecated ancient style without an explicit logging module:
 * access_log /var/log/access.log
 *
 * #2: The "none" logging module (i.e., no logging [of matching transactions]):
 * access_log none [acl ...]
 *
 * #3: Configurable logging module without named options:
 * Logformat or the first ACL name, whichever comes first, may not contain '='.
 * If no explicit logformat name is given, the first ACL name, if any,
 * should not be an existing logformat name or it will be treated as such.
 * access_log module:place [logformat_name] [acl ...]
 *
 * #4: Configurable logging module with name=value options such as logformat=x:
 * The first ACL name may not contain '='.
 * Without any optional parts, directives using this style are indistinguishable
 * from directives using style #1 until we start requiring the "module:" prefix.
 * access_log module:place [option ...] [acl ...]
 *
 */
static void
parse_access_log(CustomLog ** logs)
{
    const char *filename = ConfigParser::NextToken();
    if (!filename) {
        self_destruct();
        return;
    }

    const auto cl = new CustomLog();

    cl->filename = xstrdup(filename);

    if (strcmp(filename, "none") == 0) {
        cl->type = Log::Format::CLF_NONE;
        aclParseAclList(LegacyParser, &cl->aclList, filename);
        while (*logs)
            logs = &(*logs)->next;
        *logs = cl;
        return;
    }

    const char *token = ConfigParser::PeekAtToken();
    if (token && !strchr(token, '=')) { // style #3
        // TODO: Deprecate this style to avoid this dangerous guessing.
        if (Log::TheConfig.knownFormat(token)) {
            cl->setLogformat(token);
            (void)ConfigParser::NextToken(); // consume the token used above
        } else {
            // assume there is no explicit logformat name and use the default
            cl->setLogformat("squid");
        }
    } else { // style #1 or style #4
        // TODO: Drop deprecated style #1 support. We already warn about it, and
        // its exceptional treatment makes detecting "module" typos impractical!
        cl->parseOptions(LegacyParser, "squid");
    }
    assert(cl->type); // setLogformat() was called

    aclParseAclList(LegacyParser, &cl->aclList, cl->filename);

    while (*logs)
        logs = &(*logs)->next;

    *logs = cl;
}

static int
check_null_access_log(CustomLog *customlog_definitions)
{
    return customlog_definitions == nullptr;
}

static void
dump_access_log(StoreEntry * entry, const char *name, CustomLog * logs)
{
    assert(entry);
    for (auto log = logs; log; log = log->next) {
        {
            PackableStream os(*entry);
            os << name; // directive name
            os << ' ' << log->filename; // including "none"
            log->dumpOptions(os);
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
        delete log;
    }
}

#if HAVE_CPU_AFFINITY /* until somebody else needs this general code */
/// parses list of integers form name=N1,N2,N3,...
static bool
parseNamedIntList(const char *data, const String &name, std::vector<int> &list)
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
#endif

static void
parse_CpuAffinityMap(CpuAffinityMap **const cpuAffinityMap)
{
#if !HAVE_CPU_AFFINITY
    (void)cpuAffinityMap;
    debugs(3, DBG_CRITICAL, "FATAL: Squid built with no CPU affinity " <<
           "support, do not set 'cpu_affinity_map'");
    self_destruct();

#else /* HAVE_CPU_AFFINITY */
    if (!*cpuAffinityMap)
        *cpuAffinityMap = new CpuAffinityMap;

    const char *const pToken = ConfigParser::NextToken();
    const char *const cToken = ConfigParser::NextToken();
    std::vector<int> processes, cores;
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
#endif
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
    *cpuAffinityMap = nullptr;
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
    debugs(93, DBG_CRITICAL, "WARNING: 'icap_class' is deprecated. " <<
           "Use 'adaptation_service_set' instead");
    Adaptation::Config::ParseServiceSet();
}

static void
parse_icap_access_type()
{
    debugs(93, DBG_CRITICAL, "WARNING: 'icap_access' is deprecated. " <<
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
    cfg->service_failure_limit = GetInteger();

    if ((token = ConfigParser::NextToken()) == nullptr)
        return;

    if (strcmp(token,"in") != 0) {
        debugs(3, DBG_CRITICAL, "expecting 'in' on'"  << config_input_line << "'");
        self_destruct();
        return;
    }

    parse_time_t(&cfg->oldest_service_failure);
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

#if USE_OPENSSL
static void parse_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt)
{
    auto *al = ConfigParser::NextToken();
    if (!al) {
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
        param = nullptr;

    std::unique_ptr<sslproxy_cert_adapt> ca(new sslproxy_cert_adapt);
    if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetValidAfter]) == 0) {
        ca->alg = Ssl::algSetValidAfter;
        ca->param = xstrdup("on");
    } else if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetValidBefore]) == 0) {
        ca->alg = Ssl::algSetValidBefore;
        ca->param = xstrdup("on");
    } else if (strcmp(al, Ssl::CertAdaptAlgorithmStr[Ssl::algSetCommonName]) == 0) {
        ca->alg = Ssl::algSetCommonName;
        if (param) {
            if (strlen(param) > 64) {
                debugs(3, DBG_CRITICAL, "FATAL: sslproxy_cert_adapt: setCommonName{" <<param << "} : using common name longer than 64 bytes is not supported");
                self_destruct();
                return;
            }
            ca->param = xstrdup(param);
        }
    } else {
        debugs(3, DBG_CRITICAL, "FATAL: sslproxy_cert_adapt: unknown cert adaptation algorithm: " << al);
        self_destruct();
        return;
    }

    aclParseAclList(LegacyParser, &ca->aclList, al);

    while (*cert_adapt)
        cert_adapt = &(*cert_adapt)->next;

    *cert_adapt = ca.release();
}

static void dump_sslproxy_cert_adapt(StoreEntry *entry, const char *name, sslproxy_cert_adapt *cert_adapt)
{
    for (const auto *ca = cert_adapt; ca; ca = ca->next) {
        storeAppendPrintf(entry, "%s ", name);
        storeAppendPrintf(entry, "%s{%s} ", Ssl::sslCertAdaptAlgoritm(ca->alg), ca->param);
        if (ca->aclList)
            dump_acl_list(entry, ca->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void free_sslproxy_cert_adapt(sslproxy_cert_adapt **cert_adapt)
{
    delete *cert_adapt;
    *cert_adapt = nullptr;
}

static void parse_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign)
{
    const auto al = ConfigParser::NextToken();
    if (!al) {
        self_destruct();
        return;
    }

    std::unique_ptr<sslproxy_cert_sign> cs(new sslproxy_cert_sign);
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

    aclParseAclList(LegacyParser, &cs->aclList, al);

    while (*cert_sign)
        cert_sign = &(*cert_sign)->next;

    *cert_sign = cs.release();
}

static void dump_sslproxy_cert_sign(StoreEntry *entry, const char *name, sslproxy_cert_sign *cert_sign)
{
    for (const auto *cs = cert_sign; cs; cs = cs->next) {
        storeAppendPrintf(entry, "%s ", name);
        storeAppendPrintf(entry, "%s ", Ssl::certSignAlgorithm(cs->alg));
        if (cs->aclList)
            dump_acl_list(entry, cs->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

static void free_sslproxy_cert_sign(sslproxy_cert_sign **cert_sign)
{
    delete *cert_sign;
    *cert_sign = nullptr;
}

class sslBumpCfgRr: public ::RegisteredRunner
{
public:
    static Ssl::BumpMode lastDeprecatedRule;
    /* RegisteredRunner API */
    void finalizeConfig() override;
};

Ssl::BumpMode sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpEnd;

DefineRunnerRegistrator(sslBumpCfgRr);

void
sslBumpCfgRr::finalizeConfig()
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
    BumpCfgStyle bcsNone = nullptr;
    BumpCfgStyle bcsNew = "new client/server-first/none";
    BumpCfgStyle bcsOld = "deprecated allow/deny";
    static BumpCfgStyle bumpCfgStyleLast = bcsNone;
    BumpCfgStyle bumpCfgStyleNow = bcsNone;
    char *bm;
    if ((bm = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }

    // if this is the first rule processed
    if (*ssl_bump == nullptr) {
        bumpCfgStyleLast = bcsNone;
        sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpEnd;
    }

    auto action = Acl::Answer(ACCESS_ALLOWED);

    if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpClientFirst]) == 0) {
        action.kind = Ssl::bumpClientFirst;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpServerFirst]) == 0) {
        action.kind = Ssl::bumpServerFirst;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpPeek]) == 0) {
        action.kind = Ssl::bumpPeek;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpStare]) == 0) {
        action.kind = Ssl::bumpStare;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpSplice]) == 0) {
        action.kind = Ssl::bumpSplice;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpBump]) == 0) {
        action.kind = Ssl::bumpBump;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpTerminate]) == 0) {
        action.kind = Ssl::bumpTerminate;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, Ssl::BumpModeStr[Ssl::bumpNone]) == 0) {
        action.kind = Ssl::bumpNone;
        bumpCfgStyleNow = bcsNew;
    } else if (strcmp(bm, "allow") == 0) {
        debugs(3, DBG_CRITICAL, "SECURITY NOTICE: auto-converting deprecated "
               "\"ssl_bump allow <acl>\" to \"ssl_bump client-first <acl>\" which "
               "is usually inferior to the newer server-first "
               "bumping mode. Update your ssl_bump rules.");
        action.kind = Ssl::bumpClientFirst;
        bumpCfgStyleNow = bcsOld;
        sslBumpCfgRr::lastDeprecatedRule = Ssl::bumpClientFirst;
    } else if (strcmp(bm, "deny") == 0) {
        debugs(3, DBG_CRITICAL, "WARNING: auto-converting deprecated "
               "\"ssl_bump deny <acl>\" to \"ssl_bump none <acl>\". Update "
               "your ssl_bump rules.");
        action.kind = Ssl::bumpNone;
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

    // empty rule OK
    ParseAclWithAction(ssl_bump, action, "ssl_bump");
}

static void dump_sslproxy_ssl_bump(StoreEntry *entry, const char *name, acl_access *ssl_bump)
{
    if (ssl_bump)
        dump_SBufList(entry, ssl_bump->treeDump(name, [](const Acl::Answer &action) {
        return Ssl::BumpModeStr.at(action.kind);
    }));
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
        storeAppendPrintf(entry, "%s %s %s", name, hwa->fieldName.c_str(), hwa->fieldValue.c_str());
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
    if ((fn = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }
    HeaderWithAcl hwa;
    hwa.fieldName = fn;
    hwa.fieldId = Http::HeaderLookupTable.lookup(hwa.fieldName).id;
    if (hwa.fieldId == Http::HdrType::BAD_HDR)
        hwa.fieldId = Http::HdrType::OTHER;

    Format::Format *nlf =  new ::Format::Format("hdrWithAcl");
    ConfigParser::EnableMacros();
    String buf = ConfigParser::NextQuotedToken();
    ConfigParser::DisableMacros();
    hwa.fieldValue = buf.termedBuf();
    hwa.quoted = ConfigParser::LastTokenWasQuoted();
    if (hwa.quoted) {
        if (!nlf->parse(hwa.fieldValue.c_str())) {
            self_destruct();
            return;
        }
        hwa.valueFormat = nlf;
    } else
        delete nlf;
    aclParseAclList(LegacyParser, &hwa.aclList, (hwa.fieldName + ':' + hwa.fieldValue).c_str());
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
            hwa->valueFormat = nullptr;
        }
    }
    delete *header;
    *header = nullptr;
}

static void parse_note(Notes *notes)
{
    assert(notes);
    notes->parse(LegacyParser);
}

static void dump_note(StoreEntry *entry, const char *name, Notes &notes)
{
    notes.dump(entry, name);
}

static void free_note(Notes *notes)
{
    notes->clean();
}

static DebugMessageId ParseDebugMessageId(const char *value, const char eov)
{
    const auto id = xatoui(value, eov);
    if (!(0 < id && id < DebugMessageIdUpperBound))
        throw TextException(ToSBuf("unknown cache_log_message ID: ", value), Here());
    return static_cast<DebugMessageId>(id);
}

static void parse_cache_log_message(DebugMessages **debugMessages)
{
    DebugMessage msg;
    DebugMessageId minId = 0;
    DebugMessageId maxId = 0;

    char *key = nullptr;
    char *value = nullptr;
    while (ConfigParser::NextKvPair(key, value)) {
        if (strcmp(key, "id") == 0) {
            if (minId > 0)
                break;
            minId = maxId = ParseDebugMessageId(value, '\0');
        } else if (strcmp(key, "ids") == 0) {
            if (minId > 0)
                break;
            const auto dash = strchr(value, '-');
            if (!dash)
                throw TextException(ToSBuf("malformed cache_log_message ID range: ", key, '=', value), Here());
            minId = ParseDebugMessageId(value, '-');
            maxId = ParseDebugMessageId(dash+1, '\0');
            if (minId > maxId)
                throw TextException(ToSBuf("invalid cache_log_message ID range: ", key, '=', value), Here());
        } else if (strcmp(key, "level") == 0) {
            if (msg.levelled())
                break;
            const auto level = xatoi(value);
            if (level < 0)
                throw TextException(ToSBuf("negative cache_log_message level: ", value), Here());
            msg.level = level;
        } else if (strcmp(key, "limit") == 0) {
            if (msg.limited())
                break;
            msg.limit = xatoull(value, 10);
        } else {
            throw TextException(ToSBuf("unsupported cache_log_message option: ", key), Here());
        }
        key = value = nullptr;
    }

    if (key && value)
        throw TextException(ToSBuf("repeated or conflicting cache_log_message option: ", key, '=', value), Here());

    if (!minId)
        throw TextException("cache_log_message is missing a required id=... or ids=... option", Here());

    if (!(msg.levelled() || msg.limited()))
        throw TextException("cache_log_message is missing a required level=... or limit=... option", Here());

    assert(debugMessages);
    if (!*debugMessages)
        *debugMessages = new DebugMessages();

    for (auto id = minId; id <= maxId; ++id) {
        msg.id = id;
        (*debugMessages)->messages.at(id) = msg;
    }
}

static void dump_cache_log_message(StoreEntry *entry, const char *name, const DebugMessages *debugMessages)
{
    if (!debugMessages)
        return;

    SBufStream out;
    for (const auto &msg: debugMessages->messages) {
        if (!msg.configured())
            continue;
        out << name << " id=" << msg.id;
        if (msg.levelled())
            out << " level=" << msg.level;
        if (msg.limited())
            out << " limit=" << msg.limit;
        out << "\n";
    }
    const auto buf = out.buf();
    entry->append(buf.rawContent(), buf.length()); // may be empty
}

static void free_cache_log_message(DebugMessages **debugMessages)
{
    // clear old messages to avoid cumulative effect across (re)configurations
    assert(debugMessages);
    delete *debugMessages;
    *debugMessages = nullptr;
}

static bool FtpEspvDeprecated = false;
static void parse_ftp_epsv(acl_access **ftp_epsv)
{
    Acl::Answer ftpEpsvDeprecatedAction;
    bool ftpEpsvIsDeprecatedRule = false;

    char *t = ConfigParser::PeekAtToken();
    if (!t) {
        self_destruct();
        return;
    }

    if (!strcmp(t, "off")) {
        (void)ConfigParser::NextToken();
        ftpEpsvIsDeprecatedRule = true;
        ftpEpsvDeprecatedAction = Acl::Answer(ACCESS_DENIED);
    } else if (!strcmp(t, "on")) {
        (void)ConfigParser::NextToken();
        ftpEpsvIsDeprecatedRule = true;
        ftpEpsvDeprecatedAction = Acl::Answer(ACCESS_ALLOWED);
    }

    // Check for mixing "ftp_epsv on|off" and "ftp_epsv allow|deny .." rules:
    //   1) if this line is "ftp_epsv allow|deny ..." and already exist rules of "ftp_epsv on|off"
    //   2) if this line is "ftp_epsv on|off" and already exist rules of "ftp_epsv allow|deny ..."
    // then abort
    if ((!ftpEpsvIsDeprecatedRule && FtpEspvDeprecated) ||
            (ftpEpsvIsDeprecatedRule && !FtpEspvDeprecated && *ftp_epsv != nullptr)) {
        debugs(3, DBG_CRITICAL, "FATAL: do not mix \"ftp_epsv on|off\" cfg lines with \"ftp_epsv allow|deny ...\" cfg lines. Update your ftp_epsv rules.");
        self_destruct();
        return;
    }

    if (ftpEpsvIsDeprecatedRule) {
        // overwrite previous ftp_epsv lines
        delete *ftp_epsv;
        *ftp_epsv = nullptr;

        if (ftpEpsvDeprecatedAction == Acl::Answer(ACCESS_DENIED)) {
            if (ACL *a = ACL::FindByName("all"))
                ParseAclWithAction(ftp_epsv, ftpEpsvDeprecatedAction, "ftp_epsv", a);
            else {
                self_destruct();
                return;
            }
        }
        FtpEspvDeprecated = true;
    } else {
        aclParseAccessLine(cfg_directive, LegacyParser, ftp_epsv);
    }
}

static void dump_ftp_epsv(StoreEntry *entry, const char *name, acl_access *ftp_epsv)
{
    if (ftp_epsv)
        dump_SBufList(entry, ftp_epsv->treeDump(name, Acl::AllowOrDeny));
}

static void free_ftp_epsv(acl_access **ftp_epsv)
{
    free_acl_access(ftp_epsv);
    FtpEspvDeprecated = false;
}

/// Like parseTimeLine() but does not require the timeunit to be specified.
/// If missed, the default 'second' timeunit is assumed.
static std::chrono::seconds
ParseUrlRewriteTimeout()
{
    const auto timeValueToken = ConfigParser::NextToken();
    if (!timeValueToken)
        throw TexcHere("cannot read a time value");

    using Seconds = std::chrono::seconds;

    const auto parsedTimeValue = xatof(timeValueToken);

    if (parsedTimeValue == 0)
        return std::chrono::seconds::zero();

    std::chrono::nanoseconds parsedUnitDuration;

    const auto unitToken = ConfigParser::PeekAtToken();
    if (parseTimeUnit<Seconds>(unitToken, parsedUnitDuration))
        (void)ConfigParser::NextToken();
    else {
        const auto defaultParsed = parseTimeUnit<Seconds>(T_SECOND_STR, parsedUnitDuration);
        assert(defaultParsed);
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), ConfigParser::CurrentLocation() <<
               ": WARNING: missing time unit, using deprecated default '" << T_SECOND_STR << "'");
    }

    const auto nanoseconds = ToNanoSeconds(parsedTimeValue, parsedUnitDuration);

    return FromNanoseconds<Seconds>(nanoseconds, parsedTimeValue);
}

static void
parse_UrlHelperTimeout(SquidConfig::UrlHelperTimeout *config)
{
    // TODO: do not allow optional timeunit (as the documentation prescribes)
    // and use parseTimeLine() instead.
    Config.Timeout.urlRewrite = ParseUrlRewriteTimeout().count();

    char *key, *value;
    while(ConfigParser::NextKvPair(key, value)) {
        if (strcasecmp(key, "on_timeout") == 0) {
            if (strcasecmp(value, "bypass") == 0)
                config->action = toutActBypass;
            else if (strcasecmp(value, "fail") == 0)
                config->action = toutActFail;
            else if (strcasecmp(value, "retry") == 0)
                config->action = toutActRetry;
            else if (strcasecmp(value, "use_configured_response") == 0) {
                config->action = toutActUseConfiguredResponse;
            } else {
                debugs(3, DBG_CRITICAL, "FATAL: unsupported \"on_timeout\" action: " << value);
                self_destruct();
                return;
            }
        } else if (strcasecmp(key, "response") == 0) {
            config->response = xstrdup(value);
        } else {
            debugs(3, DBG_CRITICAL, "FATAL: unsupported option " << key);
            self_destruct();
            return;
        }
    }

    if (config->action == toutActUseConfiguredResponse && !config->response) {
        debugs(3, DBG_CRITICAL, "FATAL: Expected 'response=' option after 'on_timeout=use_configured_response' option");
        self_destruct();
    }

    if (config->action != toutActUseConfiguredResponse && config->response) {
        debugs(3, DBG_CRITICAL, "FATAL: 'response=' option is valid only when used with the 'on_timeout=use_configured_response' option");
        self_destruct();
    }
}

static void
dump_UrlHelperTimeout(StoreEntry *entry, const char *name, SquidConfig::UrlHelperTimeout &config)
{
    const char  *onTimedOutActions[] = {"bypass", "fail", "retry", "use_configured_response"};
    assert(config.action >= 0 && config.action <= toutActUseConfiguredResponse);

    dump_time_t(entry, name, Config.Timeout.urlRewrite);
    storeAppendPrintf(entry, " on_timeout=%s", onTimedOutActions[config.action]);

    if (config.response)
        storeAppendPrintf(entry, " response=\"%s\"", config.response);

    storeAppendPrintf(entry, "\n");
}

static void
free_UrlHelperTimeout(SquidConfig::UrlHelperTimeout *config)
{
    Config.Timeout.urlRewrite = 0;
    config->action = 0;
    safe_free(config->response);
}

static void
parse_configuration_includes_quoted_values(bool *)
{
    int val = 0;
    parse_onoff(&val);

    // If quoted values is set to on then enable new strict mode parsing
    if (val) {
        ConfigParser::RecognizeQuotedValues = true;
        ConfigParser::StrictMode = true;
    } else {
        ConfigParser::RecognizeQuotedValues = false;
        ConfigParser::StrictMode = false;
    }
}

static void
dump_configuration_includes_quoted_values(StoreEntry *const entry, const char *const name, bool)
{
    int val = ConfigParser::RecognizeQuotedValues ? 1 : 0;
    dump_onoff(entry, name, val);
}

static void
free_configuration_includes_quoted_values(bool *)
{
    ConfigParser::RecognizeQuotedValues = false;
    ConfigParser::StrictMode = false;
}

static void
parse_on_unsupported_protocol(acl_access **access)
{
    char *tm;
    if ((tm = ConfigParser::NextToken()) == nullptr) {
        self_destruct();
        return;
    }

    auto action = Acl::Answer(ACCESS_ALLOWED);
    if (strcmp(tm, "tunnel") == 0)
        action.kind = 1;
    else if (strcmp(tm, "respond") == 0)
        action.kind = 2;
    else {
        debugs(3, DBG_CRITICAL, "FATAL: unknown on_unsupported_protocol mode: " << tm);
        self_destruct();
        return;
    }

    // empty rule OK
    ParseAclWithAction(access, action, "on_unsupported_protocol");
}

static void
dump_on_unsupported_protocol(StoreEntry *entry, const char *name, acl_access *access)
{
    static const std::vector<const char *> onErrorTunnelMode = {
        "none",
        "tunnel",
        "respond"
    };
    if (access) {
        SBufList lines = access->treeDump(name, [](const Acl::Answer &action) {
            return onErrorTunnelMode.at(action.kind);
        });
        dump_SBufList(entry, lines);
    }
}

static void
free_on_unsupported_protocol(acl_access **access)
{
    free_acl_access(access);
}

static void
parse_http_upgrade_request_protocols(HttpUpgradeProtocolAccess **protoGuardsPtr)
{
    assert(protoGuardsPtr);
    auto &protoGuards = *protoGuardsPtr;
    if (!protoGuards)
        protoGuards = new HttpUpgradeProtocolAccess();
    protoGuards->configureGuard(LegacyParser);
}

static void
dump_http_upgrade_request_protocols(StoreEntry *entry, const char *rawName, HttpUpgradeProtocolAccess *protoGuards)
{
    if (!protoGuards)
        return;

    const SBuf name(rawName);
    protoGuards->forEach([entry,&name](const SBuf &proto, const acl_access *acls) {
        SBufList line;
        line.push_back(name);
        line.push_back(proto);
        const auto acld = acls->treeDump("", &Acl::AllowOrDeny);
        line.insert(line.end(), acld.begin(), acld.end());
        dump_SBufList(entry, line);
    });
}

static void
free_http_upgrade_request_protocols(HttpUpgradeProtocolAccess **protoGuardsPtr)
{
    assert(protoGuardsPtr);
    auto &protoGuards = *protoGuardsPtr;
    delete protoGuards;
    protoGuards = nullptr;
}

