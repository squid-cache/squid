/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
Ssl::Helper * Ssl::Helper::GetInstance()
{
    static Ssl::Helper sslHelper;
    return &sslHelper;
}

Ssl::Helper::Helper() : ssl_crtd(NULL)
{
}

Ssl::Helper::~Helper()
{
    Shutdown();
}

void Ssl::Helper::Init()
{
    assert(ssl_crtd == NULL);

    // we need to start ssl_crtd only if some port(s) need to bump SSL *and* generate certificates
    // TODO: generate host certificates for SNI enabled accel ports
    bool found = false;
    for (AnyP::PortCfgPointer s = HttpPortList; !found && s != NULL; s = s->next)
        found = s->flags.tunnelSslBumping && s->generateHostCertificates;
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

void Ssl::Helper::sslSubmit(CrtdMessage const & message, HLPCB * callback, void * data)
{
    assert(ssl_crtd);

    std::string msg = message.compose();
    msg += '\n';
    if (!ssl_crtd->trySubmit(msg.c_str(), callback, data)) {
        ::Helper::Reply failReply(::Helper::BrokenHelper);
        failReply.notes.add("message", "error 45 Temporary network problem, please retry later");
        callback(data, failReply);
        return;
    }
}
#endif //USE_SSL_CRTD

Ssl::CertValidationHelper * Ssl::CertValidationHelper::GetInstance()
{
    static Ssl::CertValidationHelper sslHelper;
    if (!Ssl::TheConfig.ssl_crt_validator)
        return NULL;
    return &sslHelper;
}

Ssl::CertValidationHelper::CertValidationHelper() : ssl_crt_validator(NULL)
{
}

Ssl::CertValidationHelper::~CertValidationHelper()
{
    Shutdown();
}

void Ssl::CertValidationHelper::Init()
{
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

class submitData
{
    CBDATA_CLASS(submitData);

public:
    std::string query;
    AsyncCall::Pointer callback;
    Security::SessionPointer ssl;
};
CBDATA_CLASS_INIT(submitData);

static void
sslCrtvdHandleReplyWrapper(void *data, const ::Helper::Reply &reply)
{
    Ssl::CertValidationMsg replyMsg(Ssl::CrtdMessage::REPLY);
    Ssl::CertValidationResponse::Pointer validationResponse = new Ssl::CertValidationResponse;
    std::string error;

    submitData *crtdvdData = static_cast<submitData *>(data);
    STACK_OF(X509) *peerCerts = SSL_get_peer_cert_chain(crtdvdData->ssl.get());
    if (reply.result == ::Helper::BrokenHelper) {
        debugs(83, DBG_IMPORTANT, "\"ssl_crtvd\" helper error response: " << reply.other().content());
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (!reply.other().hasContent()) {
        debugs(83, DBG_IMPORTANT, "\"ssl_crtvd\" helper returned NULL response");
        validationResponse->resultCode = ::Helper::BrokenHelper;
    } else if (replyMsg.parse(reply.other().content(), reply.other().contentSize()) != Ssl::CrtdMessage::OK ||
               !replyMsg.parseResponse(*validationResponse, peerCerts, error) ) {
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
        if (!Ssl::CertValidationHelper::HelperCache->add(crtdvdData->query.c_str(), item))
            delete item;
    }

    delete crtdvdData;
}

void Ssl::CertValidationHelper::sslSubmit(Ssl::CertValidationRequest const &request, AsyncCall::Pointer &callback)
{
    assert(ssl_crt_validator);

    Ssl::CertValidationMsg message(Ssl::CrtdMessage::REQUEST);
    message.setCode(Ssl::CertValidationMsg::code_cert_validate);
    message.composeRequest(request);
    debugs(83, 5, "SSL crtvd request: " << message.compose().c_str());

    submitData *crtdvdData = new submitData;
    crtdvdData->query = message.compose();
    crtdvdData->query += '\n';
    crtdvdData->callback = callback;
    crtdvdData->ssl.resetAndLock(request.ssl);
    Ssl::CertValidationResponse::Pointer const*validationResponse;

    if (CertValidationHelper::HelperCache &&
            (validationResponse = CertValidationHelper::HelperCache->get(crtdvdData->query.c_str()))) {

        CertValidationHelper::CbDialer *dialer = dynamic_cast<CertValidationHelper::CbDialer*>(callback->getDialer());
        Must(dialer);
        dialer->arg1 = *validationResponse;
        ScheduleCallHere(callback);
        delete crtdvdData;
        return;
    }

    if (!ssl_crt_validator->trySubmit(crtdvdData->query.c_str(), sslCrtvdHandleReplyWrapper, crtdvdData)) {
        Ssl::CertValidationResponse::Pointer resp = new Ssl::CertValidationResponse;;
        resp->resultCode = ::Helper::BrokenHelper;
        Ssl::CertValidationHelper::CbDialer *dialer = dynamic_cast<Ssl::CertValidationHelper::CbDialer*>(callback->getDialer());
        Must(dialer);
        dialer->arg1 = resp;
        ScheduleCallHere(callback);
        delete crtdvdData;
        return;
    }
}

