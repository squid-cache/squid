/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID__ECAP__MESSAGE_REP_H
#define SQUID__ECAP__MESSAGE_REP_H

#include "adaptation/forward.h"
#include "adaptation/Message.h"
#include "anyp/ProtocolType.h"
#include "BodyPipe.h"
#include "HttpHeader.h"
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/body.h>

class HttpMsg;
class HttpRequest;
class HttpReply;

namespace Adaptation
{
namespace Ecap
{

class XactionRep;

// Translates Squid HttpMsg into libecap::Header.
class HeaderRep: public libecap::Header
{
public:
    typedef libecap::Name Name;
    typedef libecap::Area Area;

public:
    HeaderRep(HttpMsg &aMessage);

    /* libecap::Header API */
    virtual bool hasAny(const Name &name) const;
    virtual Value value(const Name &name) const;
    virtual void add(const Name &name, const Value &value);
    virtual void removeAny(const Name &name);
    virtual void visitEach(libecap::NamedValueVisitor &visitor) const;
    virtual Area image() const;
    virtual void parse(const Area &buf); // throws on failures

protected:
    static http_hdr_type TranslateHeaderId(const Name &name);

private:
    HttpHeader &theHeader; // the header being translated to libecap
    HttpMsg &theMessage;   // the message being translated to libecap
};

// Helps translate Squid HttpMsg into libecap::FirstLine (see children).
class FirstLineRep
{
public:
    typedef libecap::Name Name;

public:
    FirstLineRep(HttpMsg &aMessage);

    libecap::Version version() const;
    void version(const libecap::Version &aVersion);
    Name protocol() const;
    void protocol(const Name &aProtocol);

protected:
    static AnyP::ProtocolType TranslateProtocolId(const Name &name);

private:
    HttpMsg &theMessage; // the message which first line is being translated
};

// Translates Squid HttpRequest into libecap::RequestLine.
class RequestLineRep: public libecap::RequestLine, public FirstLineRep
{
public:
//    typedef libecap::Name Name;
    typedef libecap::Area Area;

public:
    RequestLineRep(HttpRequest &aMessage);

    /* libecap::RequestLine API */
    virtual void uri(const Area &aUri);
    virtual Area uri() const;
    virtual void method(const Name &aMethod);
    virtual Name method() const;
    virtual libecap::Version version() const;
    virtual void version(const libecap::Version &aVersion);
    virtual Name protocol() const;
    virtual void protocol(const Name &aProtocol);

private:
    HttpRequest &theMessage; // the request header being translated to libecap
};

// Translates Squid HttpReply into libecap::StatusLine.
class StatusLineRep: public libecap::StatusLine, public FirstLineRep
{
public:
    typedef libecap::Name Name;
    typedef libecap::Area Area;

public:
    StatusLineRep(HttpReply &aMessage);

    /* libecap::StatusLine API */
    virtual void statusCode(int code);
    virtual int statusCode() const;
    virtual void reasonPhrase(const Area &phrase);
    virtual Area reasonPhrase() const;
    virtual libecap::Version version() const;
    virtual void version(const libecap::Version &aVersion);
    virtual Name protocol() const;
    virtual void protocol(const Name &aProtocol);

private:
    HttpReply &theMessage; // the request header being translated to libecap
};

// Translates Squid BodyPipe into libecap::Body.
class BodyRep: public libecap::Body
{
public:
    typedef libecap::BodySize BodySize;

public:
    BodyRep(const BodyPipe::Pointer &aBody); // using NULL pointer? see tie()

    void tie(const BodyPipe::Pointer &aBody); // late binding if !theBody;

    // libecap::Body API
    virtual BodySize bodySize() const;

private:
    BodyPipe::Pointer theBody; // the body being translated to libecap
};

// Translates Squid Adaptation::Message into libecap::Message.
class MessageRep: public libecap::Message
{
public:
    explicit MessageRep(HttpMsg *rawHeader);
    virtual ~MessageRep();

    /* libecap::Message API */
    virtual libecap::shared_ptr<libecap::Message> clone() const;
    virtual libecap::FirstLine &firstLine();
    virtual const libecap::FirstLine &firstLine() const;
    virtual libecap::Header &header();
    virtual const libecap::Header &header() const;
    virtual void addBody();
    virtual libecap::Body *body();
    virtual const libecap::Body *body() const;

    void tieBody(Ecap::XactionRep *x); // to a specific transaction

    Adaptation::Message &raw() { return theMessage; } // for host access
    const Adaptation::Message &raw() const { return theMessage; } // for host

private:
    Adaptation::Message theMessage; // the message being translated to libecap
    libecap::FirstLine *theFirstLineRep; // request or status line wrapper
    HeaderRep *theHeaderRep; // header wrapper
    BodyRep *theBodyRep; // body wrapper
};

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID__E_CAP__MESSAGE_REP_H */

