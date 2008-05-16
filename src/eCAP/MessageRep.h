
/*
 * $Id$
 */

#ifndef SQUID__ECAP__MESSAGE_REP_H
#define SQUID__ECAP__MESSAGE_REP_H

#include "adaptation/forward.h"
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/body.h>

namespace Ecap {

class XactionRep;

// Translates Squid HttpMsg into libecap::Header.
class HeaderRep: public libecap::Header
{
public:
    typedef libecap::Name Name;
    typedef libecap::Area Area;

public:
    HeaderRep(HttpMsg &aMessage);

    virtual bool hasAny(const Name &name) const;
    virtual Value value(const Name &name) const;

    virtual void add(const Name &name, const Value &value);
    virtual void removeAny(const Name &name);

    virtual Area image() const;
    virtual void parse(const Area &buf); // throws on failures

    virtual libecap::Version version() const;
    virtual void version(const libecap::Version &aVersion);
    virtual Name protocol() const;
    virtual void protocol(const Name &aProtocol);

protected:
    static http_hdr_type TranslateHeaderId(const Name &name);
    static protocol_t TranslateProtocolId(const Name &name);

private:
    HttpHeader &theHeader; // the header being translated to libecap
    HttpMsg &theMessage;   // the message being translated to libecap
};


// Translates Squid HttpRequest into libecap::Header + libecap::RequestLine.
class RequestHeaderRep: public HeaderRep, public libecap::RequestLine
{
public:
    RequestHeaderRep(HttpRequest &aMessage);

    virtual void uri(const Area &aUri);
    virtual Area uri() const;

    virtual void method(const Name &aMethod);
    virtual Name method() const;

private:
    HttpRequest &theMessage; // the request header being translated to libecap
};

// Translates Squid HttpReply into libecap::Header + libecap::StatusLine.
class ReplyHeaderRep: public HeaderRep, public libecap::StatusLine
{
public:
    ReplyHeaderRep(HttpReply &aMessage);

    virtual void statusCode(int code);
    virtual int statusCode() const;

    virtual void reasonPhrase(const Area &phrase);
    virtual Area reasonPhrase() const;

private:
    HttpReply &theMessage; // the request header being translated to libecap
};


// Translates Squid HttpMsg into libecap::Body.
class BodyRep: public libecap::Body
{
public:
    typedef libecap::Area Area;
    typedef libecap::BodySize BodySize;

public:
    BodyRep(const BodyPipe::Pointer &aBody);

    // stats
    virtual BodySize bodySize() const;
    virtual size_type consumedSize() const;
    virtual bool productionEnded() const; // producedSize will not grow
   
    // called by producers
    virtual void bodySize(const BodySize &size); // throws if already !
    virtual size_type append(const Area &area); // throws on overflow

    // called by consumers
    virtual Area prefix(size_type size) const;
    virtual void consume(size_type size);

private:
    BodyPipe::Pointer theBody; // the body being translated to libecap
};

// Translates Squid Adaptation::Message into libecap::Message.
class MessageRep: public libecap::Message
{
public:
    MessageRep(Adaptation::Message &aMessage, Ecap::XactionRep *aXaction);
    virtual ~MessageRep();

    virtual libecap::Header &header();
    virtual const libecap::Header &header() const;

    virtual void addBody();
    virtual libecap::Body *body();
    virtual const libecap::Body *body() const;

private:
    Adaptation::Message &theMessage; // the message being translated to libecap
    Ecap::XactionRep *theXaction; // host transaction managing the translation
    HeaderRep *theHeaderRep;
    BodyRep *theBodyRep;
};

} // namespace Ecap;

#endif /* SQUID__E_CAP__MESSAGE_REP_H */
