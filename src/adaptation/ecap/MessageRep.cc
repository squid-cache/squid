/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#include "squid.h"
#include "BodyPipe.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include <libecap/common/names.h>
#include <libecap/common/area.h>
#include <libecap/common/version.h>
#include <libecap/common/named_values.h>
#include "adaptation/ecap/Host.h" /* for protocol constants */
#include "adaptation/ecap/MessageRep.h"
#include "adaptation/ecap/XactionRep.h"
#include "base/TextException.h"
#include "URL.h"

/* HeaderRep */

Adaptation::Ecap::HeaderRep::HeaderRep(HttpMsg &aMessage): theHeader(aMessage.header),
    theMessage(aMessage)
{
}

bool
Adaptation::Ecap::HeaderRep::hasAny(const Name &name) const
{
    const Http::HdrType squidId = TranslateHeaderId(name);
    return squidId == Http::HdrType::OTHER ?
           theHeader.hasNamed(name.image().c_str(), name.image().size()) :
           static_cast<bool>(theHeader.has(squidId));
}

Adaptation::Ecap::HeaderRep::Value
Adaptation::Ecap::HeaderRep::value(const Name &name) const
{
    const Http::HdrType squidId = TranslateHeaderId(name);
    const String value = squidId == Http::HdrType::OTHER ?
                         theHeader.getByName(name.image().c_str()) :
                         theHeader.getStrOrList(squidId);
    return value.size() > 0 ?
           Value::FromTempString(value.termedBuf()) : Value();
}

void
Adaptation::Ecap::HeaderRep::add(const Name &name, const Value &value)
{
    const Http::HdrType squidId = TranslateHeaderId(name); // Http::HdrType::OTHER OK
    HttpHeaderEntry *e = new HttpHeaderEntry(squidId, name.image().c_str(),
            value.toString().c_str());
    theHeader.addEntry(e);

    if (squidId == Http::HdrType::CONTENT_LENGTH)
        theMessage.content_length = theHeader.getInt64(Http::HdrType::CONTENT_LENGTH);
}

void
Adaptation::Ecap::HeaderRep::removeAny(const Name &name)
{
    const Http::HdrType squidId = TranslateHeaderId(name);
    if (squidId == Http::HdrType::OTHER)
        theHeader.delByName(name.image().c_str());
    else
        theHeader.delById(squidId);

    if (squidId == Http::HdrType::CONTENT_LENGTH)
        theMessage.content_length = theHeader.getInt64(Http::HdrType::CONTENT_LENGTH);
}

void
Adaptation::Ecap::HeaderRep::visitEach(libecap::NamedValueVisitor &visitor) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    while (HttpHeaderEntry *e = theHeader.getEntry(&pos)) {
        const Name name(e->name.termedBuf()); // optimize: find std Names
        name.assignHostId(e->id);
        visitor.visit(name, Value(e->value.rawBuf(), e->value.size()));
    }
}

libecap::Area
Adaptation::Ecap::HeaderRep::image() const
{
    MemBuf mb;
    mb.init();
    theMessage.packInto(&mb, true);
    return Area::FromTempBuffer(mb.content(), mb.contentSize());
}

// throws on failures
void
Adaptation::Ecap::HeaderRep::parse(const Area &buf)
{
    Http::StatusCode error;
    Must(theMessage.parse(buf.start, buf.size, true, &error));
}

Http::HdrType
Adaptation::Ecap::HeaderRep::TranslateHeaderId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<Http::HdrType>(name.hostId());
    return Http::HdrType::OTHER;
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
    switch (theMessage.http_ver.protocol) {
    case AnyP::PROTO_HTTP:
        return libecap::protocolHttp;
    case AnyP::PROTO_HTTPS:
        return libecap::protocolHttps;
    case AnyP::PROTO_FTP:
        return libecap::protocolFtp;
    case AnyP::PROTO_GOPHER:
        return libecap::protocolGopher;
    case AnyP::PROTO_WAIS:
        return libecap::protocolWais;
    case AnyP::PROTO_WHOIS:
        return libecap::protocolWhois;
    case AnyP::PROTO_URN:
        return libecap::protocolUrn;
    case AnyP::PROTO_ICP:
        return protocolIcp;
#if USE_HTCP
    case AnyP::PROTO_HTCP:
        return protocolHtcp;
#endif
    case AnyP::PROTO_CACHE_OBJECT:
        return protocolCacheObj;
    case AnyP::PROTO_ICY:
        return protocolIcy;
    case AnyP::PROTO_COAP:
    case AnyP::PROTO_COAPS: // use 'unknown' until libecap supports coap:// and coaps://
    case AnyP::PROTO_UNKNOWN:
        return protocolUnknown; // until we remember the protocol image
    case AnyP::PROTO_NONE:
        return Name();

    case AnyP::PROTO_MAX:
        break; // should not happen
        // no default to catch AnyP::PROTO_ additions
    }
    Must(false); // not reached
    return Name();
}

void
Adaptation::Ecap::FirstLineRep::protocol(const Name &p)
{
    // TODO: what happens if we fail to translate some protocol?
    theMessage.http_ver.protocol = TranslateProtocolId(p);
}

AnyP::ProtocolType
Adaptation::Ecap::FirstLineRep::TranslateProtocolId(const Name &name)
{
    if (name.assignedHostId())
        return static_cast<AnyP::ProtocolType>(name.hostId());
    return AnyP::PROTO_UNKNOWN;
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
    const SBuf &fullUrl = theMessage.effectiveRequestUri();
    // XXX: effectiveRequestUri() cannot return NULL or even empty string, some other problem?
    Must(!fullUrl.isEmpty());
    // optimize: avoid copying by having an Area::Detail that locks theMessage
    return Area::FromTempBuffer(fullUrl.rawContent(), fullUrl.length());
}

void
Adaptation::Ecap::RequestLineRep::method(const Name &aMethod)
{
    if (aMethod.assignedHostId()) {
        const int id = aMethod.hostId();
        Must(Http::METHOD_NONE < id && id < Http::METHOD_ENUM_END);
        Must(id != Http::METHOD_OTHER);
        theMessage.method = HttpRequestMethod(static_cast<Http::MethodType>(id));
    } else {
        const std::string &image = aMethod.image();
        theMessage.method.HttpRequestMethodXXX(image.c_str());
    }
}

Adaptation::Ecap::RequestLineRep::Name
Adaptation::Ecap::RequestLineRep::method() const
{
    switch (theMessage.method.id()) {
    case Http::METHOD_GET:
        return libecap::methodGet;
    case Http::METHOD_POST:
        return libecap::methodPost;
    case Http::METHOD_PUT:
        return libecap::methodPut;
    case Http::METHOD_HEAD:
        return libecap::methodHead;
    case Http::METHOD_CONNECT:
        return libecap::methodConnect;
    case Http::METHOD_DELETE:
        return libecap::methodDelete;
    case Http::METHOD_TRACE:
        return libecap::methodTrace;
    default:
        return Name(theMessage.method.image().toStdString());
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
    theMessage.sline.set(theMessage.sline.version, static_cast<Http::StatusCode>(code), nullptr);
}

int
Adaptation::Ecap::StatusLineRep::statusCode() const
{
    // TODO: remove cast when possible
    return static_cast<int>(theMessage.sline.status());
}

void
Adaptation::Ecap::StatusLineRep::reasonPhrase(const Area &)
{
    // Squid does not support external custom reason phrases so we have
    // to just reset it (in case there was a custom internal reason set)
    theMessage.sline.resetReason();
}

Adaptation::Ecap::StatusLineRep::Area
Adaptation::Ecap::StatusLineRep::reasonPhrase() const
{
    return Area::FromTempString(std::string(theMessage.sline.reason()));
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
    return (theBody != nullptr && theBody->bodySizeKnown()) ? BodySize(theBody->bodySize()) : BodySize();
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

