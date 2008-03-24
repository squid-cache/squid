/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "ConfigParser.h"
#include "adaptation/Service.h"

Adaptation::Service::Service(): 
    port(-1), method(methodNone), point(pointNone), bypass(false)
{}

Adaptation::Service::~Service()
{}

const char *
Adaptation::Service::methodStr() const
{
    return Adaptation::methodStr(method);
}

const char *
Adaptation::Service::vectPointStr() const
{
    return Adaptation::vectPointStr(point);
}

Adaptation::Method
Adaptation::Service::parseMethod(const char *str) const
{
    if (!strncasecmp(str, "REQMOD", 6))
        return Adaptation::methodReqmod;

    if (!strncasecmp(str, "RESPMOD", 7))
        return Adaptation::methodRespmod;

    return Adaptation::methodNone;
}

Adaptation::VectPoint
Adaptation::Service::parseVectPoint(const char *service) const
{
    const char *t = service;
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
Adaptation::Service::configure()
{
    char *service_type = NULL;

    ConfigParser::ParseString(&key);
    ConfigParser::ParseString(&service_type);
    ConfigParser::ParseBool(&bypass);
    ConfigParser::ParseString(&uri);

    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
        key.buf() << " " << service_type << " " << bypass);

    method = parseMethod(service_type);
    point = parseVectPoint(service_type);

    debugs(3, 5, HERE << cfg_filename << ':' << config_lineno << ": " <<
        "service is " << methodStr() << "_" << vectPointStr());

    if (false && uri.cmp("icap://", 7) != 0) { // XXX: parametrize and enable
        debugs(3, 0, HERE << cfg_filename << ':' << config_lineno << ": " <<
            "wrong service URI protocol: " << uri.buf());
        return false;
    }

    const char *s = uri.buf() + 7;

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

    // if no port, the caller may use services or supply the default if neeeded

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
