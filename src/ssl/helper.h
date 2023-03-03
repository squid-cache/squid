/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_HELPER_H
#define SQUID_SSL_HELPER_H

#if USE_OPENSSL

#include "base/AsyncJobCalls.h"
#include "base/ClpMap.h"
#include "helper/forward.h"
#include "security/forward.h"
#include "ssl/cert_validate_message.h"
#include "ssl/crtd_message.h"

namespace Ssl
{
#if USE_SSL_CRTD
/**
 * Set of thread for ssl_crtd. This class is singleton.
 * This class use helper structure for threads management.
 */
class Helper
{
public:
    static void Init(); ///< Init helper structure.
    static void Shutdown(); ///< Shutdown helper structure.
    static void Reconfigure(); ///< Reconfigure helper structure.
    /// Submit crtd message to external crtd server.
    static void Submit(CrtdMessage const & message, HLPCB * callback, void *data);
private:
    static helper * ssl_crtd; ///< helper for management of ssl_crtd.
};
#endif

class CertValidationRequest;
class CertValidationResponse;
class CertValidationHelper
{
public:
    using Answer = CertValidationResponse::Pointer;
    using Callback = AsyncCallback<Answer>;

    typedef void CVHCB(void *, Ssl::CertValidationResponse const &);
    static void Init(); ///< Init helper structure.
    static void Shutdown(); ///< Shutdown helper structure.
    static void Reconfigure(); ///< Reconfigure helper structure
    /// Submit crtd request message to external crtd server.
    static void Submit(const Ssl::CertValidationRequest &, const Callback &);
private:
    static helper * ssl_crt_validator; ///< helper for management of ssl_crtd.
public:
    typedef ClpMap<SBuf, CertValidationResponse::Pointer, CertValidationResponse::MemoryUsedByResponse> CacheType;
    static CacheType *HelperCache; ///< cache for cert validation helper
};

} //namespace Ssl

#endif /* USE_OPENSSL */
#endif // SQUID_SSL_HELPER_H

