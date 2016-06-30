/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    Adaptation */

#include "squid.h"
#include "adaptation/ServiceConfig.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "globals.h"
#include "ip/tools.h"
#include <set>

Adaptation::ServiceConfig::ServiceConfig():
    port(-1), method(methodNone), point(pointNone),
    bypass(false), maxConn(-1), onOverload(srvWait),
    routing(false), ipv6(false)
{}

const char *
Adaptation::ServiceConfig::methodStr() const
{
    return Adaptation::methodStr(method);
}

const char *
Adaptation::ServiceConfig::vectPointStr() const
{
    return Adaptation::vectPointStr(point);
}

Adaptation::Method
Adaptation::ServiceConfig::parseMethod(const char *str) const
{
    if (!strncasecmp(str, "REQMOD", 6))
        return Adaptation::methodReqmod;

    if (!strncasecmp(str, "RESPMOD", 7))
        return Adaptation::methodRespmod;

    return Adaptation::methodNone;
}

Adaptation::VectPoint
Adaptation::ServiceConfig::parseVectPoint(const char *service_configConfig) const
{
    const char *t = service_configConfig;
    const char *q = strchr(t, '_');

    if (q)
        t = q + 1;

    if (!strcmp(t, "precache"))
        return Adaptation::pointPreCache;

    if (!strcmp(t, "postcache"))
        return Adaptation::pointPostCache;

    return Adaptation::pointNone;
}

bool
Adaptation::ServiceConfig::parse()
{
    key = ConfigParser::NextToken();
    String method_point = ConfigParser::NextToken();
    if (!method_point.size()) {
        debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' << config_lineno << ": " <<
               "Missing vectoring point in adaptation service definition");
        return false;
    }

    method = parseMethod(method_point.termedBuf());
    point = parseVectPoint(method_point.termedBuf());
    if (method == Adaptation::methodNone && point == Adaptation::pointNone) {
        debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' << config_lineno << ": " <<
               "Unknown vectoring point '" << method_point << "' in adaptation service definition");
        return false;
    }

    // reset optional parameters in case we are reconfiguring
    bypass = routing = false;

    // handle optional service name=value parameters
    bool grokkedUri = false;
    bool onOverloadSet = false;
    std::set<std::string> options;

    while (char *option = ConfigParser::NextToken()) {
        const char *name = option;
        const char *value = "";
        if (strcmp(option, "0") == 0) { // backward compatibility
            name = "bypass";
            value = "off";
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "UPGRADE: Please use 'bypass=off' option to disable service bypass");
        }  else if (strcmp(option, "1") == 0) { // backward compatibility
            name = "bypass";
            value = "on";
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "UPGRADE: Please use 'bypass=on' option to enable service bypass");
        } else {
            char *eq = strstr(option, "=");
            const char *sffx = strstr(option, "://");
            if (!eq || (sffx && sffx < eq)) { //no "=" or has the form "icap://host?arg=val"
                name = "uri";
                value = option;
            }  else { // a normal name=value option
                *eq = '\0'; // terminate option name
                value = eq + 1; // skip '='
            }
        }

        // Check if option is set twice
        if (options.find(name) != options.end()) {
            debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' << config_lineno << ": " <<
                   "Duplicate option \"" << name << "\" in adaptation service definition");
            return false;
        }
        options.insert(name);

        bool grokked = false;
        if (strcmp(name, "bypass") == 0) {
            grokked = grokBool(bypass, name, value);
        } else if (strcmp(name, "routing") == 0)
            grokked = grokBool(routing, name, value);
        else if (strcmp(name, "uri") == 0)
            grokked = grokkedUri = grokUri(value);
        else if (strcmp(name, "ipv6") == 0) {
            grokked = grokBool(ipv6, name, value);
            if (grokked && ipv6 && !Ip::EnableIpv6)
                debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: IPv6 is disabled. ICAP service option ignored.");
        } else if (strcmp(name, "max-conn") == 0)
            grokked = grokLong(maxConn, name, value);
        else if (strcmp(name, "on-overload") == 0) {
            grokked = grokOnOverload(onOverload, value);
            onOverloadSet = true;
        } else
            grokked = grokExtension(name, value);

        if (!grokked)
            return false;
    }

    // set default on-overload value if needed
    if (!onOverloadSet)
        onOverload = bypass ? srvBypass : srvWait;

    // is the service URI set?
    if (!grokkedUri) {
        debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' << config_lineno << ": " <<
               "No \"uri\" option in adaptation service definition");
        return false;
    }

    debugs(3,5, cfg_filename << ':' << config_lineno << ": " <<
           "adaptation_service " << key << ' ' <<
           methodStr() << "_" << vectPointStr() << ' ' <<
           bypass << routing << ' ' <<
           uri);

    return true;
}

bool
Adaptation::ServiceConfig::grokUri(const char *value)
{
    // TODO: find core code that parses URLs and extracts various parts
    // AYJ: most of this is duplicate of urlParse() in src/url.cc

    if (!value || !*value) {
        debugs(3, DBG_CRITICAL, HERE << cfg_filename << ':' << config_lineno << ": " <<
               "empty adaptation service URI");
        return false;
    }

    uri = value;

    // extract scheme and use it as the service_configConfig protocol
    const char *schemeSuffix = "://";
    const String::size_type schemeEnd = uri.find(schemeSuffix);
    if (schemeEnd != String::npos)
        protocol=uri.substr(0,schemeEnd);

    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
           "service protocol is " << protocol);

    if (protocol.size() == 0)
        return false;

    // skip scheme
    const char *s = uri.termedBuf() + protocol.size() + strlen(schemeSuffix);

    const char *e;

    bool have_port = false;

    int len = 0;
    if (*s == '[') {
        const char *t;
        if ((t = strchr(s, ']')) == NULL)
            return false;

        ++s;
        len = t - s;
        if ((e = strchr(t, ':')) != NULL) {
            have_port = true;
        } else if ((e = strchr(t, '/')) != NULL) {
            have_port = false;
        } else {
            return false;
        }
    } else {
        if ((e = strchr(s, ':')) != NULL) {
            have_port = true;
        } else if ((e = strchr(s, '/')) != NULL) {
            have_port = false;
        } else {
            return false;
        }
        len = e - s;
    }

    host.limitInit(s, len);
    s = e;

    port = -1;
    if (have_port) {
        ++s;

        if ((e = strchr(s, '/')) != NULL) {
            char *t;
            const unsigned long p = strtoul(s, &t, 0);

            if (p > 65535) // port value is too high
                return false;

            port = static_cast<int>(p);

            if (t != e) // extras after the port
                return false;

            s = e;

            if (s[0] != '/')
                return false;
        }
    }

    // if no port, the caller may use service_configConfigs or supply the default if neeeded

    ++s;
    e = strchr(s, '\0');
    len = e - s;

    if (len > 1024) {
        debugs(3, DBG_CRITICAL, HERE << cfg_filename << ':' << config_lineno << ": " <<
               "long resource name (>1024), probably wrong");
    }

    resource.limitInit(s, len + 1);
    return true;
}

bool
Adaptation::ServiceConfig::grokBool(bool &var, const char *name, const char *value)
{
    if (!strcmp(value, "0") || !strcmp(value, "off"))
        var = false;
    else if (!strcmp(value, "1") || !strcmp(value, "on"))
        var = true;
    else {
        debugs(3, DBG_CRITICAL, HERE << cfg_filename << ':' << config_lineno << ": " <<
               "wrong value for boolean " << name << "; " <<
               "'0', '1', 'on', or 'off' expected but got: " << value);
        return false;
    }

    return true;
}

bool
Adaptation::ServiceConfig::grokLong(long &var, const char *name, const char *value)
{
    char *bad = NULL;
    const long p = strtol(value, &bad, 0);
    if (p < 0 || bad == value) {
        debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' <<
               config_lineno << ": " << "wrong value for " << name << "; " <<
               "a non-negative integer expected but got: " << value);
        return false;
    }
    var = p;
    return true;
}

bool
Adaptation::ServiceConfig::grokOnOverload(SrvBehaviour &var, const char *value)
{
    if (strcmp(value, "block") == 0)
        var = srvBlock;
    else if (strcmp(value, "bypass") == 0)
        var = srvBypass;
    else if (strcmp(value, "wait") == 0)
        var = srvWait;
    else if (strcmp(value, "force") == 0)
        var = srvForce;
    else {
        debugs(3, DBG_CRITICAL, "ERROR: " << cfg_filename << ':' <<
               config_lineno << ": " << "wrong value for on-overload; " <<
               "'block', 'bypass', 'wait' or 'force' expected but got: " << value);
        return false;
    }
    return true;
}

bool
Adaptation::ServiceConfig::grokExtension(const char *name, const char *value)
{
    // we do not accept extensions by default
    debugs(3, DBG_CRITICAL, cfg_filename << ':' << config_lineno << ": " <<
           "ERROR: unknown adaptation service option: " <<
           name << '=' << value);
    return false;
}

