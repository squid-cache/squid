/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "../helper.h"
#include "anyp/PortCfg.h"
#include "fs_io.h"
#include "helper/Reply.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/helper.h"
#include "wordlist.h"

Ssl::CertValidationHelper::LruCache *Ssl::CertValidationHelper::HelperCache = nullptr;

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
    assert(ssl_crtd == NULL);

    // we need to start ssl_crtd only if some port(s) need to bump SSL *and* generate certificates
    // TODO: generate host certificates for SNI enabled accel ports
    bool found = false;
    for (AnyP::PortCfgPointer s = HttpPortList; !found && s != NULL; s = s->next)
        found = s->flags.tunnelSslBumping && s->secure.generateHostCertificates;
    if (!found)
        return;

    ssl_crtd = new helper(Ssl::TheConfig.ssl_crtd);
    ssl_crtd->childs.updateLimits(Ssl::TheConfig.ssl_crtdChildren);
    ssl_crtd->ipc_type = IPC_STREAM;
    // The crtd messages may contain the eol ('\n') character. We are
    // going to use the '\1' char as the end-of-message mark.
    ssl_crtd->eom = '\1';
    assert(ssl_crtd->cmdline == NULL);
    {
        char *tmp = xstrdup(Ssl::TheConfig.ssl_crtd);
        char *tmp_begin = tmp;
        char *token = NULL;
        while ((token = strwordtok(NULL, &tmp))) {
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
    ssl_crtd = NULL;
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

    assert(ssl_crt_validator == NULL);

    // we need to start ssl_crtd only if some port(s) need to bump SSL
    bool found = false;
    for (AnyP::PortCfgPointer s = HttpPortList; !found && s != NULL; s = s->next)
        found = s->flags.tunnelSslBumping;
    if (!found)
        return;

    ssl_crt_validator = new helper("ssl_crt_validator");
    ssl_crt_validator->childs.updateLimits(Ssl::TheConfig.ssl_crt_validator_Children);
    ssl_crt_validator->ipc_type = IPC_STREAM;
    // The crtd messages may contain the eol ('\n') character. We are
    // going to use the '\1' char as the end-of-message mark.
    ssl_crt_validator->eom = '\1';
    assert(ssl_crt_validator->cmdline == NULL);

    int ttl = 60;
    size_t cache = 2048;
    {
        char *tmp = xstrdup(Ssl::TheConfig.ssl_crt_validator);
        char *tmp_begin = tmp;
        char * token = NULL;
        bool parseParams = true;
        while ((token = strwordtok(NULL, &tmp))) {
            if (parseParams) {
                if (strncmp(token, "ttl=", 4) == 0) {
                    ttl = atoi(token + 4);
                    continue;
                } else if (strncmp(token, "cache=", 6) == 0) {
                    cache = atoi(token + 6);
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
    assert(HelperCache == NULL);
    HelperCache = new Ssl::CertValidationHelper::LruCache(ttl, cache);
}

void Ssl::CertValidationHelper::Shutdown()
{
    if (!ssl_crt_validator)
        return;
    helperShutdown(ssl_crt_validator);
    wordlistDestroy(&ssl_crt_validator->cmdline);
    delete ssl_crt_validator;
    ssl_crt_validator = NULL;

    // CertValidationHelper::HelperCache is a static member, it is not good policy to
    // reset it here. Will work because the current Ssl::CertValidationHelper is
    // always the same static object.
    delete HelperCache;
    HelperCache = NULL;
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
    AsyncCall::Pointer callback;
    Security::SessionPointer ssl;
};
CBDATA_CLASS_INIT(submitData);

static void
sslCrtvdHandleReplyWrapper(void *data, const ::Helper::Reply &reply)
{
    Ssl::CertValidationMsg replyMsg(Ssl::CrtdMessage::REPLY);
    std::string error;

    submitData *crtdvdData = static_cast<submitData *>(data);
    assert(crtdvdData->ssl.get());
    Ssl::CertValidationResponse::Pointer validationResponse = new Ssl::CertValidationResponse(crtdvdData->ssl);
    if (reply.result == ::Helper::BrokenHelper) {
        debugs(83, DBG_IMPORTANT, "\"ssl_crtvd\" helper error response: " << reply.other().content());
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (!reply.other().hasContent()) {
        debugs(83, DBG_IMPORTANT, "\"ssl_crtvd\" helper returned NULL response");
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (replyMsg.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK ||
               !replyMsg.parseResponse(*validationResponse, error) ) {
        debugs(83, DBG_IMPORTANT, "WARNING: Reply from ssl_crtvd for " << " is incorrect");
        debugs(83, DBG_IMPORTANT, "Certificate cannot be validated. ssl_crtvd response: " << replyMsg.getBody());
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else
        validationResponse->resultCode = reply.result;

    Ssl::CertValidationHelper::CbDialer *dialer = dynamic_cast<Ssl::CertValidationHelper::CbDialer*>(crtdvdData->callback->getDialer());
    Must(dialer);
    dialer->arg1 = validationResponse;
    ScheduleCallHere(crtdvdData->callback);

    if (Ssl::CertValidationHelper::HelperCache &&
            (validationResponse->resultCode == ::Helper::Okay || validationResponse->resultCode == ::Helper::Error)) {
        Ssl::CertValidationResponse::Pointer *item = new Ssl::CertValidationResponse::Pointer(validationResponse);
        if (!Ssl::CertValidationHelper::HelperCache->add(crtdvdData->query, item))
            delete item;
    }

    delete crtdvdData;
}

void Ssl::CertValidationHelper::Submit(Ssl::CertValidationRequest const &request, AsyncCall::Pointer &callback)
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

        CertValidationHelper::CbDialer *dialer = dynamic_cast<CertValidationHelper::CbDialer*>(callback->getDialer());
        Must(dialer);
        dialer->arg1 = *validationResponse;
        ScheduleCallHere(callback);
        delete crtdvdData;
        return;
    }

    // ssl_crt_validator becomes nil if Squid is reconfigured with cert
    // validator disabled in the new configuration
    if (ssl_crt_validator && ssl_crt_validator->trySubmit(crtdvdData->query.c_str(), sslCrtvdHandleReplyWrapper, crtdvdData))
        return;

    Ssl::CertValidationResponse::Pointer resp = new Ssl::CertValidationResponse(crtdvdData->ssl);
    resp->resultCode = ::Helper::BrokenHelper;
    Ssl::CertValidationHelper::CbDialer *dialer = dynamic_cast<Ssl::CertValidationHelper::CbDialer*>(callback->getDialer());
    Must(dialer);
    dialer->arg1 = resp;
    ScheduleCallHere(callback);
    delete crtdvdData;
    return;
}

