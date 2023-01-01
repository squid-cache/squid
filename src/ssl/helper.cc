/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "../helper.h"
#include "anyp/PortCfg.h"
#include "base/AsyncCallbacks.h"
#include "cache_cf.h"
#include "fs_io.h"
#include "helper/Reply.h"
#include "Parsing.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/helper.h"
#include "wordlist.h"

#include <limits>

Ssl::CertValidationHelper::CacheType *Ssl::CertValidationHelper::HelperCache = nullptr;

#if USE_SSL_CRTD

namespace Ssl {

/// Initiator of an Ssl::Helper query.
class GeneratorRequestor {
public:
    GeneratorRequestor(HLPCB *aCallback, void *aData): callback(aCallback), data(aData) {}
    HLPCB *callback;
    CallbackData data;
};

/// A pending Ssl::Helper request, combining the original and collapsed queries.
class GeneratorRequest {
    CBDATA_CLASS(GeneratorRequest);

public:
    /// adds a GeneratorRequestor
    void emplace(HLPCB *callback, void *data) { requestors.emplace_back(callback, data); }

    SBuf query; ///< Ssl::Helper request message (GeneratorRequests key)

    /// Ssl::Helper request initiators waiting for the same answer (FIFO).
    typedef std::vector<GeneratorRequestor> GeneratorRequestors;
    GeneratorRequestors requestors;
};

/// Ssl::Helper query:GeneratorRequest map
typedef std::unordered_map<SBuf, GeneratorRequest*> GeneratorRequests;

static void HandleGeneratorReply(void *data, const ::Helper::Reply &reply);

} // namespace Ssl

CBDATA_NAMESPACED_CLASS_INIT(Ssl, GeneratorRequest);

/// prints Ssl::GeneratorRequest for debugging
static std::ostream &
operator <<(std::ostream &os, const Ssl::GeneratorRequest &gr)
{
    return os << "crtGenRq" << gr.query.id.value << "/" << gr.requestors.size();
}

/// pending Ssl::Helper requests (to all certificate generator helpers combined)
static Ssl::GeneratorRequests TheGeneratorRequests;

helper *Ssl::Helper::ssl_crtd = nullptr;

void Ssl::Helper::Init()
{
    assert(ssl_crtd == nullptr);

    // we need to start ssl_crtd only if some port(s) need to bump SSL *and* generate certificates
    // TODO: generate host certificates for SNI enabled accel ports
    bool found = false;
    for (AnyP::PortCfgPointer s = HttpPortList; !found && s != nullptr; s = s->next)
        found = s->flags.tunnelSslBumping && s->secure.generateHostCertificates;
    if (!found)
        return;

    ssl_crtd = new helper("sslcrtd_program");
    ssl_crtd->childs.updateLimits(Ssl::TheConfig.ssl_crtdChildren);
    ssl_crtd->ipc_type = IPC_STREAM;
    // The crtd messages may contain the eol ('\n') character. We are
    // going to use the '\1' char as the end-of-message mark.
    ssl_crtd->eom = '\1';
    assert(ssl_crtd->cmdline == nullptr);
    {
        char *tmp = xstrdup(Ssl::TheConfig.ssl_crtd);
        char *tmp_begin = tmp;
        char *token = nullptr;
        while ((token = strwordtok(nullptr, &tmp))) {
            wordlistAdd(&ssl_crtd->cmdline, token);
        }
        safe_free(tmp_begin);
    }
    helperOpenServers(ssl_crtd);
}

void Ssl::Helper::Shutdown()
{
    if (!ssl_crtd)
        return;
    helperShutdown(ssl_crtd);
    wordlistDestroy(&ssl_crtd->cmdline);
    delete ssl_crtd;
    ssl_crtd = nullptr;
}

void
Ssl::Helper::Reconfigure()
{
    Shutdown();
    Init();
}

void Ssl::Helper::Submit(CrtdMessage const & message, HLPCB * callback, void * data)
{
    SBuf rawMessage(message.compose().c_str()); // XXX: helpers cannot use SBuf
    rawMessage.append("\n", 1);

    const auto pending = TheGeneratorRequests.find(rawMessage);
    if (pending != TheGeneratorRequests.end()) {
        pending->second->emplace(callback, data);
        debugs(83, 5, "collapsed request from " << data << " onto " << *pending->second);
        return;
    }

    GeneratorRequest *request = new GeneratorRequest;
    request->query = rawMessage;
    request->emplace(callback, data);
    TheGeneratorRequests.emplace(request->query, request);
    debugs(83, 5, "request from " << data << " as " << *request);
    // ssl_crtd becomes nil if Squid is reconfigured without SslBump or
    // certificate generation disabled in the new configuration
    if (ssl_crtd && ssl_crtd->trySubmit(request->query.c_str(), HandleGeneratorReply, request))
        return;

    ::Helper::Reply failReply(::Helper::BrokenHelper);
    failReply.notes.add("message", "error 45 Temporary network problem, please retry later");
    HandleGeneratorReply(request, failReply);
}

/// receives helper response
static void
Ssl::HandleGeneratorReply(void *data, const ::Helper::Reply &reply)
{
    const std::unique_ptr<Ssl::GeneratorRequest> request(static_cast<Ssl::GeneratorRequest*>(data));
    assert(request);
    const auto erased = TheGeneratorRequests.erase(request->query);
    assert(erased);

    for (auto &requestor: request->requestors) {
        if (void *cbdata = requestor.data.validDone()) {
            debugs(83, 5, "to " << cbdata << " in " << *request);
            requestor.callback(cbdata, reply);
        }
    }
}
#endif //USE_SSL_CRTD

helper *Ssl::CertValidationHelper::ssl_crt_validator = nullptr;

void Ssl::CertValidationHelper::Init()
{
    if (!Ssl::TheConfig.ssl_crt_validator)
        return;

    assert(ssl_crt_validator == nullptr);

    // we need to start ssl_crtd only if some port(s) need to bump SSL
    bool found = false;
    for (AnyP::PortCfgPointer s = HttpPortList; !found && s != nullptr; s = s->next)
        found = s->flags.tunnelSslBumping;
    if (!found)
        return;

    ssl_crt_validator = new helper("ssl_crt_validator");
    ssl_crt_validator->childs.updateLimits(Ssl::TheConfig.ssl_crt_validator_Children);
    ssl_crt_validator->ipc_type = IPC_STREAM;
    // The crtd messages may contain the eol ('\n') character. We are
    // going to use the '\1' char as the end-of-message mark.
    ssl_crt_validator->eom = '\1';
    assert(ssl_crt_validator->cmdline == nullptr);

    /* defaults */
    int ttl = 3600; // 1 hour
    size_t cache = 64*1024*1024; // 64 MB
    {
        // TODO: Do this during parseConfigFile() for proper parsing, error handling
        char *tmp = xstrdup(Ssl::TheConfig.ssl_crt_validator);
        char *tmp_begin = tmp;
        char * token = nullptr;
        bool parseParams = true;
        while ((token = strwordtok(nullptr, &tmp))) {
            if (parseParams) {
                if (strcmp(token, "ttl=infinity") == 0) {
                    ttl = std::numeric_limits<CacheType::Ttl>::max();
                    continue;
                } else if (strncmp(token, "ttl=", 4) == 0) {
                    ttl = xatoi(token + 4);
                    if (ttl < 0) {
                        throw TextException(ToSBuf("Negative TTL in sslcrtvalidator_program ", Ssl::TheConfig.ssl_crt_validator,
                                                   Debug::Extra, "For unlimited TTL, use ttl=infinity"),
                                            Here());
                    }
                    continue;
                } else if (strncmp(token, "cache=", 6) == 0) {
                    cache = xatoi(token + 6);
                    continue;
                } else
                    parseParams = false;
            }
            wordlistAdd(&ssl_crt_validator->cmdline, token);
        }
        xfree(tmp_begin);
    }
    helperOpenServers(ssl_crt_validator);

    //WARNING: initializing static member in an object initialization method
    assert(HelperCache == nullptr);
    HelperCache = new CacheType(cache, ttl);
}

void Ssl::CertValidationHelper::Shutdown()
{
    if (!ssl_crt_validator)
        return;
    helperShutdown(ssl_crt_validator);
    wordlistDestroy(&ssl_crt_validator->cmdline);
    delete ssl_crt_validator;
    ssl_crt_validator = nullptr;

    // CertValidationHelper::HelperCache is a static member, it is not good policy to
    // reset it here. Will work because the current Ssl::CertValidationHelper is
    // always the same static object.
    delete HelperCache;
    HelperCache = nullptr;
}

void
Ssl::CertValidationHelper::Reconfigure()
{
    Shutdown();
    Init();
}

class submitData
{
    CBDATA_CLASS(submitData);

public:
    SBuf query;
    Ssl::CertValidationHelper::Callback callback;
    Security::SessionPointer ssl;
};
CBDATA_CLASS_INIT(submitData);

static void
sslCrtvdHandleReplyWrapper(void *data, const ::Helper::Reply &reply)
{
    Ssl::CertValidationMsg replyMsg(Ssl::CrtdMessage::REPLY);

    submitData *crtdvdData = static_cast<submitData *>(data);
    assert(crtdvdData->ssl.get());
    Ssl::CertValidationResponse::Pointer validationResponse = new Ssl::CertValidationResponse(crtdvdData->ssl);
    if (reply.result == ::Helper::BrokenHelper) {
        debugs(83, DBG_IMPORTANT, "ERROR: \"ssl_crtvd\" helper error response: " << reply.other().content());
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (!reply.other().hasContent()) {
        debugs(83, DBG_IMPORTANT, "\"ssl_crtvd\" helper returned NULL response");
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (replyMsg.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK ||
               !replyMsg.parseResponse(*validationResponse) ) {
        debugs(83, DBG_IMPORTANT, "WARNING: Reply from ssl_crtvd for " << " is incorrect");
        debugs(83, DBG_IMPORTANT, "ERROR: Certificate cannot be validated. ssl_crtvd response: " << replyMsg.getBody());
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else
        validationResponse->resultCode = reply.result;

    crtdvdData->callback.answer() = validationResponse;
    ScheduleCallHere(crtdvdData->callback.release());

    if (Ssl::CertValidationHelper::HelperCache &&
            (validationResponse->resultCode == ::Helper::Okay || validationResponse->resultCode == ::Helper::Error)) {
        (void)Ssl::CertValidationHelper::HelperCache->add(crtdvdData->query, validationResponse);
    }

    delete crtdvdData;
}

void
Ssl::CertValidationHelper::Submit(const Ssl::CertValidationRequest &request, const Callback &callback)
{
    Ssl::CertValidationMsg message(Ssl::CrtdMessage::REQUEST);
    message.setCode(Ssl::CertValidationMsg::code_cert_validate);
    message.composeRequest(request);
    debugs(83, 5, "SSL crtvd request: " << message.compose().c_str());

    submitData *crtdvdData = new submitData;
    crtdvdData->query.assign(message.compose().c_str());
    crtdvdData->query.append('\n');
    crtdvdData->callback = callback;
    crtdvdData->ssl = request.ssl;
    Ssl::CertValidationResponse::Pointer const*validationResponse;

    if (CertValidationHelper::HelperCache &&
            (validationResponse = CertValidationHelper::HelperCache->get(crtdvdData->query))) {

        crtdvdData->callback.answer() = *validationResponse;
        ScheduleCallHere(crtdvdData->callback.release());
        delete crtdvdData;
        return;
    }

    // ssl_crt_validator becomes nil if Squid is reconfigured with cert
    // validator disabled in the new configuration
    if (ssl_crt_validator && ssl_crt_validator->trySubmit(crtdvdData->query.c_str(), sslCrtvdHandleReplyWrapper, crtdvdData))
        return;

    Ssl::CertValidationResponse::Pointer resp = new Ssl::CertValidationResponse(crtdvdData->ssl);
    resp->resultCode = ::Helper::BrokenHelper;
    crtdvdData->callback.answer() = resp;
    ScheduleCallHere(crtdvdData->callback.release());
    delete crtdvdData;
    return;
}

