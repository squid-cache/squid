/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "BodyPipe.h"
#include "TextException.h"
#include <libecap/common/names.h>
#include <libecap/common/area.h>
#include <libecap/common/version.h>
#include "adaptation/ecap/MessageRep.h"
#include "adaptation/ecap/XactionRep.h"
#include "adaptation/ecap/Host.h" /* for protocol constants */

/* HeaderRep */

Adaptation::Ecap::HeaderRep::HeaderRep(HttpMsg &aMessage): theHeader(aMessage.header),
        theMessage(aMessage)
{
}

bool
Adaptation::Ecap::HeaderRep::hasAny(const Name &name) const
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    // XXX: optimize to remove getByName: we do not need the value here
    return squidId == HDR_OTHER ?
           theHeader.getByName(name.image().c_str()).size() > 0:
           (bool)theHeader.has(squidId);
}

Adaptation::Ecap::HeaderRep::Value
Adaptation::Ecap::HeaderRep::value(const Name &name) const
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    const String value = squidId == HDR_OTHER ?
                         theHeader.getByName(name.image().c_str()) :
                         theHeader.getStrOrList(squidId);
    return Value::FromTempString(value.termedBuf());
}

void
Adaptation::Ecap::HeaderRep::add(const Name &name, const Value &value)
{
    const http_hdr_type squidId = TranslateHeaderId(name); // HDR_OTHER OK
    HttpHeaderEntry *e = new HttpHeaderEntry(squidId, name.image().c_str(),
            value.toString().c_str());
    theHeader.addEntry(e);
}

void
Adaptation::Ecap::HeaderRep::removeAny(const Name &name)
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    if (squidId == HDR_OTHER)
        theHeader.delByName(name.image().c_str());
    else
        theHeader.delById(squidId);
}

libecap::Area
Adaptation::Ecap::HeaderRep::image() const
{
    MemBuf mb;
    mb.init();

    Packer p;
    packerToMemInit(&p, &mb);
    theMessage.packInto(&p, true);
    packerClean(&p);
    return Area::FromTempBuffer(mb.content(), mb.contentSize());
}

// throws on failures
void
Adaptation::Ecap::HeaderRep::parse(const Area &buf)
{
    MemBuf mb;
    mb.init();
    mb.append(buf.start, buf.size);
    http_status error;
    Must(theMessage.parse(&mb, true, &error));
}

http_hdr_type
Adaptation::Ecap::HeaderRep::TranslateHeaderId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<http_hdr_type>(name.hostId());
    return HDR_OTHER;
}


/* FirstLineRep */

Adaptation::Ecap::FirstLineRep::FirstLineRep(HttpMsg &aMessage): theMessage(aMessage)
{
}

libecap::Version
Adaptation::Ecap::FirstLineRep::version() const
{
    return libecap::Version(theMessage.http_ver.major,
                            theMessage.http_ver.minor);
}

void
Adaptation::Ecap::FirstLineRep::version(const libecap::Version &aVersion)
{
    theMessage.http_ver.major = aVersion.majr;
    theMessage.http_ver.minor = aVersion.minr;
}

libecap::Name
Adaptation::Ecap::FirstLineRep::protocol() const
{
    // TODO: optimize?
    switch (theMessage.protocol) {
    case PROTO_HTTP:
        return libecap::protocolHttp;
    case PROTO_HTTPS:
        return libecap::protocolHttps;
    case PROTO_FTP:
        return libecap::protocolFtp;
    case PROTO_GOPHER:
        return libecap::protocolGopher;
    case PROTO_WAIS:
        return libecap::protocolWais;
    case PROTO_WHOIS:
        return libecap::protocolWhois;
    case PROTO_URN:
        return libecap::protocolUrn;
    case PROTO_ICP:
        return protocolIcp;
#if USE_HTCP
    case PROTO_HTCP:
        return protocolHtcp;
#endif
    case PROTO_CACHEOBJ:
        return protocolCacheObj;
    case PROTO_INTERNAL:
        return protocolInternal;
    case PROTO_ICY:
        return Name();
    case PROTO_NONE:
        return Name();

    case PROTO_MAX:
        break; // should not happen
        // no default to catch PROTO_ additions
    }
    Must(false); // not reached
    return Name();
}

void
Adaptation::Ecap::FirstLineRep::protocol(const Name &p)
{
    // TODO: what happens if we fail to translate some protocol?
    theMessage.protocol = TranslateProtocolId(p);
}

protocol_t
Adaptation::Ecap::FirstLineRep::TranslateProtocolId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<protocol_t>(name.hostId());
    return PROTO_NONE; // no PROTO_OTHER
}


/* RequestHeaderRep */

Adaptation::Ecap::RequestLineRep::RequestLineRep(HttpRequest &aMessage):
        FirstLineRep(aMessage), theMessage(aMessage)
{
}

void
Adaptation::Ecap::RequestLineRep::uri(const Area &aUri)
{
    // TODO: if method is not set, urlPath will assume it is not connect;
    // Can we change urlParse API to remove the method parameter?
    // TODO: optimize: urlPath should take constant URL buffer
    char *buf = xstrdup(aUri.toString().c_str());
    const bool ok = urlParse(theMessage.method, buf, &theMessage);
    xfree(buf);
    Must(ok);
}

Adaptation::Ecap::RequestLineRep::Area
Adaptation::Ecap::RequestLineRep::uri() const
{
    return Area::FromTempBuffer(theMessage.urlpath.rawBuf(),
                                theMessage.urlpath.size());
}

void
Adaptation::Ecap::RequestLineRep::method(const Name &aMethod)
{
    if (aMethod.assignedHostId()) {
        const int id = aMethod.hostId();
        Must(METHOD_NONE < id && id < METHOD_ENUM_END);
        Must(id != METHOD_OTHER);
        theMessage.method = HttpRequestMethod(static_cast<_method_t>(id));
    } else {
        const std::string &image = aMethod.image();
        theMessage.method = HttpRequestMethod(image.data(),
                                              image.data() + image.size());
    }
}

Adaptation::Ecap::RequestLineRep::Name
Adaptation::Ecap::RequestLineRep::method() const
{
    switch (theMessage.method.id()) {
    case METHOD_GET:
        return libecap::methodGet;
    case METHOD_POST:
        return libecap::methodPost;
    case METHOD_PUT:
        return libecap::methodPut;
    case METHOD_HEAD:
        return libecap::methodHead;
    case METHOD_CONNECT:
        return libecap::methodConnect;
    case METHOD_DELETE:
        return libecap::methodDelete;
    case METHOD_TRACE:
        return libecap::methodTrace;
    default:
        return Name(theMessage.method.image());
    }
}

libecap::Version
Adaptation::Ecap::RequestLineRep::version() const
{
    return FirstLineRep::version();
}

void
Adaptation::Ecap::RequestLineRep::version(const libecap::Version &aVersion)
{
    FirstLineRep::version(aVersion);
}

libecap::Name
Adaptation::Ecap::RequestLineRep::protocol() const
{
    return FirstLineRep::protocol();
}

void
Adaptation::Ecap::RequestLineRep::protocol(const Name &p)
{
    FirstLineRep::protocol(p);
}


/* ReplyHeaderRep */

Adaptation::Ecap::StatusLineRep::StatusLineRep(HttpReply &aMessage):
        FirstLineRep(aMessage), theMessage(aMessage)
{
}

void
Adaptation::Ecap::StatusLineRep::statusCode(int code)
{
    // TODO: why is .status a enum? Do we not support unknown statuses?
    theMessage.sline.status = static_cast<http_status>(code);
}

int
Adaptation::Ecap::StatusLineRep::statusCode() const
{
    // TODO: see statusCode(code) TODO above
    return static_cast<int>(theMessage.sline.status);
}

void
Adaptation::Ecap::StatusLineRep::reasonPhrase(const Area &)
{
    // Squid does not support custom reason phrases
    theMessage.sline.reason = NULL;
}

Adaptation::Ecap::StatusLineRep::Area
Adaptation::Ecap::StatusLineRep::reasonPhrase() const
{
    return theMessage.sline.reason ?
           Area::FromTempString(std::string(theMessage.sline.reason)) : Area();
}

libecap::Version
Adaptation::Ecap::StatusLineRep::version() const
{
    return FirstLineRep::version();
}

void
Adaptation::Ecap::StatusLineRep::version(const libecap::Version &aVersion)
{
    FirstLineRep::version(aVersion);
}

libecap::Name
Adaptation::Ecap::StatusLineRep::protocol() const
{
    return FirstLineRep::protocol();
}

void
Adaptation::Ecap::StatusLineRep::protocol(const Name &p)
{
    FirstLineRep::protocol(p);
}

/* BodyRep */

Adaptation::Ecap::BodyRep::BodyRep(const BodyPipe::Pointer &aBody): theBody(aBody)
{
}

void
Adaptation::Ecap::BodyRep::tie(const BodyPipe::Pointer &aBody)
{
    Must(!theBody);
    Must(aBody != NULL);
    theBody = aBody;
}

Adaptation::Ecap::BodyRep::BodySize
Adaptation::Ecap::BodyRep::bodySize() const
{
    return !theBody ? BodySize() : BodySize(theBody->bodySize());
}


/* MessageRep */

Adaptation::Ecap::MessageRep::MessageRep(HttpMsg *rawHeader):
        theMessage(rawHeader), theFirstLineRep(NULL),
        theHeaderRep(NULL), theBodyRep(NULL)
{
    Must(theMessage.header); // we do not want to represent a missing message

    if (HttpRequest *req = dynamic_cast<HttpRequest*>(theMessage.header))
        theFirstLineRep = new RequestLineRep(*req);
    else if (HttpReply *rep = dynamic_cast<HttpReply*>(theMessage.header))
        theFirstLineRep = new StatusLineRep(*rep);
    else
        Must(false); // unknown message header type

    theHeaderRep = new HeaderRep(*theMessage.header);

    if (theMessage.body_pipe != NULL)
        theBodyRep = new BodyRep(theMessage.body_pipe);
}

Adaptation::Ecap::MessageRep::~MessageRep()
{
    delete theBodyRep;
    delete theHeaderRep;
    delete theFirstLineRep;
}

libecap::shared_ptr<libecap::Message>
Adaptation::Ecap::MessageRep::clone() const
{
    HttpMsg *hdr = theMessage.header->clone();
    hdr->body_pipe = NULL; // if any; TODO: remove pipe cloning from ::clone?
    libecap::shared_ptr<libecap::Message> res(new MessageRep(hdr));

    // restore indication of a body if needed, but not the pipe
    if (theMessage.header->body_pipe != NULL)
        res->addBody();

    return res;
}

libecap::FirstLine &
Adaptation::Ecap::MessageRep::firstLine()
{
    return *theFirstLineRep;
}

const libecap::FirstLine &
Adaptation::Ecap::MessageRep::firstLine() const
{
    return *theFirstLineRep;
}

libecap::Header &
Adaptation::Ecap::MessageRep::header()
{
    return *theHeaderRep;
}

const libecap::Header &
Adaptation::Ecap::MessageRep::header() const
{
    return *theHeaderRep;
}

libecap::Body *
Adaptation::Ecap::MessageRep::body()
{
    return theBodyRep;
}

void
Adaptation::Ecap::MessageRep::addBody()
{
    Must(!theBodyRep);
    Must(!theMessage.body_pipe); // set in tieBody()
    theBodyRep = new BodyRep(NULL);
}

void
Adaptation::Ecap::MessageRep::tieBody(Adaptation::Ecap::XactionRep *x)
{
    Must(theBodyRep != NULL); // addBody must be called first
    Must(!theMessage.header->body_pipe);
    Must(!theMessage.body_pipe);
    theMessage.header->body_pipe = new BodyPipe(x);
    theMessage.body_pipe = theMessage.header->body_pipe;
    theBodyRep->tie(theMessage.body_pipe);
}

const libecap::Body *Adaptation::Ecap::MessageRep::body() const
{
    return theBodyRep;
}
