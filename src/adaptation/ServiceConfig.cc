/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "ConfigParser.h"
#include "adaptation/ServiceConfig.h"

Adaptation::ServiceConfig::ServiceConfig():
        port(-1), method(methodNone), point(pointNone), bypass(false)
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
    ConfigParser::ParseBool(&bypass);
    ConfigParser::ParseString(&uri);

    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
           key.buf() << " " << method_point << " " << bypass);

    method = parseMethod(method_point);
    point = parseVectPoint(method_point);
    safe_free(method_point);

    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
           "service_configConfig is " << methodStr() << "_" << vectPointStr());

    // TODO: find core code that parses URLs and extracts various parts

    // extract scheme and use it as the service_configConfig protocol
    const char *schemeSuffix = "://";
    if (const char *schemeEnd = uri.pos(schemeSuffix))
        protocol.limitInit(uri.buf(), schemeEnd - uri.buf());
    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
           "service protocol is " << protocol);
    if (!protocol.size())
        return false;

    // skip scheme
    const char *s = uri.buf() + protocol.size() + strlen(schemeSuffix);

    const char *e;

    bool have_port = false;

    if ((e = strchr(s, ':')) != NULL) {
        have_port = true;
    } else if ((e = strchr(s, '/')) != NULL) {
        have_port = false;
    } else {
        return false;
    }

    int len = e - s;
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

    if ((bypass != 0) && (bypass != 1)) {
        debugs(3, 0, HERE << cfg_filename << ':' << config_lineno << ": " <<
               "wrong bypass value; 0 or 1 expected: " << bypass);
        return false;
    }

    return true;
}
