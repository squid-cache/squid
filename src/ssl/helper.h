/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_HELPER_H
#define SQUID_SSL_HELPER_H

#if USE_OPENSSL

#include "base/AsyncJobCalls.h"
#include "base/LruMap.h"
#include "helper/forward.h"
#include "security/forward.h"
#include "ssl/cert_validate_message.h"
#include "ssl/crtd_message.h"

namespace Ssl
{
#if USE_SSL_CRTD
/**
 * Set of thread for ssl_crtd. This class is singleton. Use this class only
 * over GetIntance() static method. This class use helper structure
 * for threads management.
 */
class Helper
{
public:
    static Helper * GetInstance(); ///< Instance class.
    void Init(); ///< Init helper structure.
    void Shutdown(); ///< Shutdown helper structure.
    /// Submit crtd message to external crtd server.
    void sslSubmit(CrtdMessage const & message, HLPCB * callback, void *data);
private:
    Helper();
    ~Helper();

    helper * ssl_crtd; ///< helper for management of ssl_crtd.
};
#endif

class CertValidationRequest;
class CertValidationResponse;
class CertValidationHelper
{
public:
    typedef UnaryMemFunT<Security::PeerConnector, CertValidationResponse::Pointer> CbDialer;

    typedef void CVHCB(void *, Ssl::CertValidationResponse const &);
    static CertValidationHelper * GetInstance(); ///< Instance class.
    void Init(); ///< Init helper structure.
    void Shutdown(); ///< Shutdown helper structure.
    /// Submit crtd request message to external crtd server.
    void sslSubmit(Ssl::CertValidationRequest const & request, AsyncCall::Pointer &);
private:
    CertValidationHelper();
    ~CertValidationHelper();

    helper * ssl_crt_validator; ///< helper for management of ssl_crtd.
public:
    typedef LruMap<Ssl::CertValidationResponse::Pointer, sizeof(Ssl::CertValidationResponse::Pointer) + sizeof(Ssl::CertValidationResponse)> LruCache;
    static LruCache *HelperCache; ///< cache for cert validation helper
};

} //namespace Ssl

#endif /* USE_OPENSSL */
#endif // SQUID_SSL_HELPER_H

