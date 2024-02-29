/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID_SRC_ADAPTATION_ECAP_MESSAGEREP_H
#define SQUID_SRC_ADAPTATION_ECAP_MESSAGEREP_H

#include "adaptation/forward.h"
#include "adaptation/Message.h"
#include "anyp/ProtocolType.h"
#include "BodyPipe.h"
#include "http/forward.h"
#include "HttpHeader.h"

#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/body.h>

namespace Adaptation
{
namespace Ecap
{

class XactionRep;

// Translates Squid Http::Message into libecap::Header.
class HeaderRep: public libecap::Header
{
public:
    typedef libecap::Name Name;
    typedef libecap::Area Area;

public:
    HeaderRep(Http::Message &aMessage);

    /* libecap::Header API */
    bool hasAny(const Name &name) const override;
    Value value(const Name &name) const override;
    void add(const Name &name, const Value &value) override;
    void removeAny(const Name &name) override;
    void visitEach(libecap::NamedValueVisitor &visitor) const override;
    Area image() const override;
    void parse(const Area &buf) override; // throws on failures

protected:
    static Http::HdrType TranslateHeaderId(const Name &name);

private:
    HttpHeader &theHeader; // the header being translated to libecap
    Http::Message &theMessage;   // the message being translated to libecap
};

// Helps translate Squid Http::Message into libecap::FirstLine (see children).
class FirstLineRep
{
public:
    typedef libecap::Name Name;

public:
    FirstLineRep(Http::Message &aMessage);

    libecap::Version version() const;
    void version(const libecap::Version &aVersion);
    Name protocol() const;
    void protocol(const Name &aProtocol);

protected:
    static AnyP::ProtocolType TranslateProtocolId(const Name &name);

private:
    Http::Message &theMessage; // the message which first line is being translated
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
    void uri(const Area &aUri) override;
    Area uri() const override;
    void method(const Name &aMethod) override;
    Name method() const override;
    libecap::Version version() const override;
    void version(const libecap::Version &aVersion) override;
    Name protocol() const override;
    void protocol(const Name &aProtocol) override;

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
    void statusCode(int code) override;
    int statusCode() const override;
    void reasonPhrase(const Area &phrase) override;
    Area reasonPhrase() const override;
    libecap::Version version() const override;
    void version(const libecap::Version &aVersion) override;
    Name protocol() const override;
    void protocol(const Name &aProtocol) override;

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
    BodySize bodySize() const override;

private:
    BodyPipe::Pointer theBody; // the body being translated to libecap
};

// Translates Squid Adaptation::Message into libecap::Message.
class MessageRep: public libecap::Message
{
public:
    explicit MessageRep(Http::Message *rawHeader);
    ~MessageRep() override;

    /* libecap::Message API */
    libecap::shared_ptr<libecap::Message> clone() const override;
    libecap::FirstLine &firstLine() override;
    const libecap::FirstLine &firstLine() const override;
    libecap::Header &header() override;
    const libecap::Header &header() const override;
    void addBody() override;
    libecap::Body *body() override;
    const libecap::Body *body() const override;

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

#endif /* SQUID_SRC_ADAPTATION_ECAP_MESSAGEREP_H */

