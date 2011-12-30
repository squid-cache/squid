/*
 * auth_ntlm.h
 * Internal declarations for the ntlm auth module
 */

#ifndef __AUTH_NTLM_H__
#define __AUTH_NTLM_H__
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "helper.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

class HttpRequest;
class StoreEntry;

namespace Auth
{
namespace Ntlm
{

/** NTLM Authentication configuration data */
class Config : public Auth::Config
{
public:
    Config();
    virtual bool active() const;
    virtual bool configured() const;
    virtual Auth::UserRequest::Pointer decode(char const *proxy_auth);
    virtual void done();
    virtual void rotateHelpers();
    virtual void dump(StoreEntry *, const char *, Auth::Config *);
    virtual void fixHeader(Auth::UserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(Auth::Config *);
    virtual void parse(Auth::Config *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;

public:
    int keep_alive;
};

} // namespace Ntlm
} // namespace Auth

extern statefulhelper *ntlmauthenticators;

#endif
