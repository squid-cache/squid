/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "BodyPipe.h"
#include "TextException.h"
#include "adaptation/Message.h"
#include <libecap/common/names.h>
#include <libecap/common/area.h>
#include <libecap/common/version.h>
#include "eCAP/MessageRep.h"
#include "eCAP/XactionRep.h"
#include "eCAP/Host.h" /* for protocol constants */

/* HeaderRep */

Ecap::HeaderRep::HeaderRep(HttpMsg &aMessage): theHeader(aMessage.header),
    theMessage(aMessage)
{
}

http_hdr_type
Ecap::HeaderRep::TranslateHeaderId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<http_hdr_type>(name.hostId());
    return HDR_OTHER;
}

protocol_t
Ecap::HeaderRep::TranslateProtocolId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<protocol_t>(name.hostId());
    return PROTO_NONE; // no PROTO_OTHER
}

bool
Ecap::HeaderRep::hasAny(const Name &name) const
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    // XXX: optimize to remove getByName: we do not need the value here
    return squidId == HDR_OTHER ?
        theHeader.getByName(name.image().c_str()).size() > 0:
        (bool)theHeader.has(squidId);
}

Ecap::HeaderRep::Value
Ecap::HeaderRep::value(const Name &name) const
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    const String value = squidId == HDR_OTHER ?
        theHeader.getByName(name.image().c_str()) :
        theHeader.getStrOrList(squidId);
    return Value::FromTempString(value.buf());
}

void
Ecap::HeaderRep::add(const Name &name, const Value &value)
{
    const http_hdr_type squidId = TranslateHeaderId(name); // HDR_OTHER OK
    HttpHeaderEntry *e = new HttpHeaderEntry(squidId, name.image().c_str(),
        value.toString().c_str());
    theHeader.addEntry(e);
}

void
Ecap::HeaderRep::removeAny(const Name &name)
{
    const http_hdr_type squidId = TranslateHeaderId(name);
    if (squidId == HDR_OTHER)
        theHeader.delByName(name.image().c_str());
    else
        theHeader.delById(squidId);
}

libecap::Area
Ecap::HeaderRep::image() const
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
Ecap::HeaderRep::parse(const Area &buf)
{
    MemBuf mb;
    mb.init();
    mb.append(buf.start, buf.size);
    http_status error;
    Must(theMessage.parse(&mb, true, &error));
}

libecap::Version
Ecap::HeaderRep::version() const
{
    return libecap::Version(theMessage.http_ver.major,
        theMessage.http_ver.minor);
}

void
Ecap::HeaderRep::version(const libecap::Version &aVersion)
{
    theMessage.http_ver.major = aVersion.majr;
    theMessage.http_ver.minor = aVersion.minr;
}

libecap::Name
Ecap::HeaderRep::protocol() const
{
    // TODO: optimize?
    switch (theMessage.protocol) {
        case PROTO_HTTP: return libecap::protocolHttp;
        case PROTO_HTTPS: return libecap::protocolHttps;
        case PROTO_FTP: return libecap::protocolFtp;
        case PROTO_GOPHER: return libecap::protocolGopher;
        case PROTO_WAIS: return libecap::protocolWais;
        case PROTO_WHOIS: return libecap::protocolWhois;
        case PROTO_URN: return libecap::protocolUrn;
        case PROTO_ICP: return protocolIcp;
#if USE_HTCP
        case PROTO_HTCP: return protocolHtcp;
#endif
        case PROTO_CACHEOBJ: return protocolCacheObj;
        case PROTO_INTERNAL: return protocolInternal;
        case PROTO_NONE: return Name();

        case PROTO_MAX: break; // should not happen
        // no default to catch PROTO_ additions
    }
    Must(false); // not reached
    return Name();
}

void
Ecap::HeaderRep::protocol(const Name &p)
{
    // TODO: what happens if we fail to translate some protocol?
    theMessage.protocol = TranslateProtocolId(p);
}


/* RequestHeaderRep */

Ecap::RequestHeaderRep::RequestHeaderRep(HttpRequest &aMessage):
    HeaderRep(aMessage), theMessage(aMessage)
{
}

void
Ecap::RequestHeaderRep::uri(const Area &aUri)
{
    // TODO: if method is not set, urlPath will assume it is not connect;
    // Can we change urlParse API to remove the method parameter?
    // TODO: optimize: urlPath should take constant URL buffer
    char *buf = xstrdup(aUri.toString().c_str());
    const bool ok = urlParse(theMessage.method, buf, &theMessage);
    xfree(buf);
    Must(ok);
}

Ecap::RequestHeaderRep::Area
Ecap::RequestHeaderRep::uri() const
{
    return Area::FromTempBuffer(theMessage.urlpath.buf(),
        theMessage.urlpath.size());
}

void
Ecap::RequestHeaderRep::method(const Name &aMethod)
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

Ecap::RequestHeaderRep::Name
Ecap::RequestHeaderRep::method() const
{
    switch (theMessage.method.id()) {
        case METHOD_GET: return libecap::methodGet;
        case METHOD_POST: return libecap::methodPost;
        case METHOD_PUT: return libecap::methodPut;
        case METHOD_HEAD: return libecap::methodHead;
        case METHOD_CONNECT: return libecap::methodConnect;
        case METHOD_DELETE: return libecap::methodDelete;
        case METHOD_TRACE: return libecap::methodTrace;
        default: return Name(theMessage.method.image());
    }
}


/* ReplyHeaderRep */

Ecap::ReplyHeaderRep::ReplyHeaderRep(HttpReply &aMessage):
    HeaderRep(aMessage), theMessage(aMessage)
{
}

void
Ecap::ReplyHeaderRep::statusCode(int code)
{
    // TODO: why is .status a enum? Do we not support unknown statuses?
    theMessage.sline.status = static_cast<http_status>(code);
}

int
Ecap::ReplyHeaderRep::statusCode() const
{
    // TODO: see statusCode(code) TODO above
    return static_cast<int>(theMessage.sline.status);
}

void
Ecap::ReplyHeaderRep::reasonPhrase(const Area &)
{
    // Squid does not support custom reason phrases
    theMessage.sline.reason = NULL;
}

Ecap::ReplyHeaderRep::Area
Ecap::ReplyHeaderRep::reasonPhrase() const
{
    return theMessage.sline.reason ?
        Area::FromTempString(std::string(theMessage.sline.reason)) : Area();
}


/* BodyRep */

Ecap::BodyRep::BodyRep(const BodyPipe::Pointer &aBody): theBody(aBody)
{
}

Ecap::BodyRep::BodySize
Ecap::BodyRep::bodySize() const
{
    return BodySize(theBody->bodySize());
}

Ecap::BodyRep::size_type
Ecap::BodyRep::consumedSize() const
{
    return theBody->consumedSize();
}

bool
Ecap::BodyRep::productionEnded() const
{
    return theBody->productionEnded();
}
   
void
Ecap::BodyRep::bodySize(const Ecap::BodyRep::BodySize &size)
{
    Must(size.known());
    theBody->setBodySize(size.value());
}

Ecap::BodyRep::size_type
Ecap::BodyRep::append(const Ecap::BodyRep::Area &area)
{
    return theBody->putMoreData(area.start, area.size);
}

Ecap::BodyRep::Area
Ecap::BodyRep::prefix(Ecap::BodyRep::size_type size) const
{
    Must(size <= static_cast<size_type>(theBody->buf().contentSize()));
    // XXX: optimize by making theBody a shared_ptr (see FromTemp*() src)
    return Area::FromTempBuffer(theBody->buf().content(), size);
}

void
Ecap::BodyRep::consume(Ecap::BodyRep::size_type size)
{
    theBody->consume(size);
}


/* MessageRep */

Ecap::MessageRep::MessageRep(Adaptation::Message &aMessage,
    Ecap::XactionRep *aXaction):
    theMessage(aMessage), theXaction(aXaction),
    theHeaderRep(NULL), theBodyRep(NULL)
{
    Must(theMessage.header); // we do not want to represent a missing message

    if (HttpRequest *req = dynamic_cast<HttpRequest*>(theMessage.header))
        theHeaderRep = new RequestHeaderRep(*req);
    else
    if (HttpReply *rep = dynamic_cast<HttpReply*>(theMessage.header))
        theHeaderRep = new ReplyHeaderRep(*rep);
    else
	    Must(false); // unknown message header type

    if (theMessage.body_pipe != NULL)
        theBodyRep = new BodyRep(theMessage.body_pipe);
}

Ecap::MessageRep::~MessageRep()
{
    delete theHeaderRep;
}

libecap::Header &
Ecap::MessageRep::header()
{
    return *theHeaderRep;
}

const libecap::Header &
Ecap::MessageRep::header() const
{
    return *theHeaderRep;
}

libecap::Body *
Ecap::MessageRep::body()
{
    return theBodyRep;
}

void
Ecap::MessageRep::addBody()
{
    Must(theXaction);
    Must(!theBodyRep);
    Must(!theMessage.body_pipe);
    theMessage.body_pipe = new BodyPipe(theXaction);
    theBodyRep = new BodyRep(theMessage.body_pipe);
}

const libecap::Body *Ecap::MessageRep::body() const
{
    return theBodyRep;
}
