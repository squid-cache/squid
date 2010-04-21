/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "ConfigParser.h"
#include "adaptation/ServiceConfig.h"

Adaptation::ServiceConfig::ServiceConfig():
        port(-1), method(methodNone), point(pointNone),
        bypass(false), routing(false)
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

    if (!strcasecmp(t, "precache"))
        return Adaptation::pointPreCache;

    if (!strcasecmp(t, "postcache"))
        return Adaptation::pointPostCache;

    return Adaptation::pointNone;
}

bool
Adaptation::ServiceConfig::parse()
{
    char *method_point = NULL;

    ConfigParser::ParseString(&key);
    ConfigParser::ParseString(&method_point);
    method = parseMethod(method_point);
    point = parseVectPoint(method_point);

    // reset optional parameters in case we are reconfiguring
    bypass = routing = false;

    // handle optional service name=value parameters
    const char *lastOption = NULL;
    while (char *option = strtok(NULL, w_space)) {
        if (strcmp(option, "0") == 0) { // backward compatibility
            bypass = false;
            continue;
        }
        if (strcmp(option, "1") == 0) { // backward compatibility
            bypass = true;
            continue;
        }

        const char *name = option;
        char *value = strstr(option, "=");
        if (!value) {
            lastOption = option;
            break;
        }
        *value = '\0'; // terminate option name
        ++value; // skip '='

        // TODO: warn if option is set twice?
        bool grokked = false;
        if (strcmp(name, "bypass") == 0)
            grokked = grokBool(bypass, name, value);
        else if (strcmp(name, "routing") == 0)
            grokked = grokBool(routing, name, value);
        else {
            debugs(3, 0, cfg_filename << ':' << config_lineno << ": " <<
                   "unknown adaptation service option: " << name << '=' << value);
        }
        if (!grokked)
            return false;
    }

    // what is left must be the service URI
    if (!grokUri(lastOption))
        return false;

    // there should be nothing else left
    if (const char *tail = strtok(NULL, w_space)) {
        debugs(3, 0, cfg_filename << ':' << config_lineno << ": " <<
               "garbage after adaptation service URI: " << tail);
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
        debugs(3, 0, HERE << cfg_filename << ':' << config_lineno << ": " <<
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

        s++;
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
        s++;

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

    s++;
    e = strchr(s, '\0');
    len = e - s;

    if (len > 1024) {
        debugs(3, 0, HERE << cfg_filename << ':' << config_lineno << ": " <<
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
        debugs(3, 0, HERE << cfg_filename << ':' << config_lineno << ": " <<
               "wrong value for boolean " << name << "; " <<
               "'0', '1', 'on', or 'off' expected but got: " << value);
        return false;
    }

    return true;
}
