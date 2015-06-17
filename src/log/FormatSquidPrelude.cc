/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 46    Access Log - Squid format 
 * AUTHOR: CSSI (Selim Menouar, Verene Houdebine)
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "format/Quoting.h"
#include "format/Token.h"
#include "globals.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "ip/Address.h"

#ifndef PRELUDE

void
Log::Format::SquidPrelude(const AccessLogEntry::Pointer &al, Logfile * logfile)
{
    debugs(50, false, "You have to compile with libprelude using ./configure --enable-prelude");
}

#else

#include <libprelude/prelude.h>


int
AdditionalDataString(idmef_alert_t *alert, const char *meaning, const char *ptr){
    int ret;
    prelude_string_t *str;
    idmef_additional_data_t *ad;
    idmef_data_t *data;

    ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
    if ( ret < 0 )
        return ret;
    idmef_additional_data_set_type(ad, IDMEF_ADDITIONAL_DATA_TYPE_STRING);
    ret = idmef_additional_data_new_data(ad, &data);
    if ( ret < 0 )
        return ret;
    idmef_data_set_char_string_ref(data, ptr);
    ret = idmef_additional_data_new_meaning(ad, &str);
    if ( ret < 0 )
        return ret;
    prelude_string_set_ref(str, meaning);

    return 1;
}

int
AdditionalDataInteger(idmef_alert_t *alert, const char *meaning, int data){
    prelude_string_t *str;
    idmef_additional_data_t *ad;
    int ret;

    ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
    if ( ret < 0 )
        return ret;
    idmef_additional_data_set_integer(ad, data);
    ret = idmef_additional_data_new_meaning(ad, &str);
    if ( ret < 0 )
        return ret;
    prelude_string_set_ref(str, meaning);

    return 1;
}

void
Log::Format::SquidPrelude(const AccessLogEntry::Pointer &al, Logfile * logfile)
{
    int ret;
    idmef_message_t *idmef = NULL;
    idmef_alert_t *alert;
    idmef_classification_t *classification;
    idmef_reference_t *reference;
    idmef_target_t *target;
    idmef_service_t *service;
    idmef_web_service_t *webservice;
    idmef_source_t *source;
    idmef_node_t *nodes;
    idmef_address_t *addresss;
    idmef_assessment_t *assessment;
    idmef_confidence_t *confidence;
    idmef_impact_t *impact;
    prelude_string_t *str;
    prelude_client_t *prelude_client = (prelude_client_t *)logfile->data;

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    static SBuf method;

    if (al->_private.method_str)
        method = al->http.method.image();
    else
        method = al->http.method.image();

    if( al->cache.code == 12 ){

        ret = idmef_message_new(&idmef);
        if ( ret < 0 )
            goto err;

        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
            goto err;

        ret = idmef_alert_new_classification(alert, &classification);
        if ( ret < 0 )
            goto err;

        ret = idmef_classification_new_text(classification, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_constant(str, "Proxy ACL violation attempt");

        ret = idmef_alert_new_target(alert, &target, 0);
        if ( ret < 0 )
            goto err;

        ret = idmef_target_new_service(target, &service);
        if ( ret < 0 )
            goto err;

        ret = idmef_service_new_web_service(service, &webservice);
        if ( ret < 0 )
            goto err;

        ret = idmef_web_service_new_url(webservice, &str);
        if ( ret < 0 )
            goto err;
        prelude_string_set_constant(str, al->url);

        ret = idmef_service_new_protocol(service, &str);
        if ( ret < 0 )
            goto err;
        prelude_string_set_ref(str, AnyP::ProtocolType_str[al->http.version.protocol]);

        ret = idmef_alert_new_source(alert, &source, 0);
        if ( ret < 0 )
            goto err;

        ret = idmef_source_new_node(source, &nodes);
        if ( ret < 0 )
            goto err;

        ret = idmef_node_new_address(nodes, &addresss, 0);
        if ( ret < 0 )
            goto err;

        ret = idmef_address_new_address(addresss, &str);
        if ( ret < 0 )
            goto err;
        prelude_string_set_ref(str, clientip);

        idmef_address_set_category(addresss, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);

        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
            goto err;

        ret = idmef_assessment_new_confidence(assessment, &confidence);
        if ( ret < 0 )
            goto err;

        idmef_confidence_set_rating(confidence, IDMEF_CONFIDENCE_RATING_HIGH);

        ret = idmef_assessment_new_impact(assessment, &impact);
        if ( ret < 0 )
            goto err;

        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_MEDIUM);

        idmef_impact_set_completion(impact, IDMEF_IMPACT_COMPLETION_FAILED);

        ret = idmef_impact_new_description(impact, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_constant(str, "Host tried to violate Squid ACL");
        ret = idmef_classification_new_reference(classification, &reference, 0);
        if ( ret < 0 )
            goto err;

        idmef_reference_set_origin(reference, IDMEF_REFERENCE_ORIGIN_VENDOR_SPECIFIC);
        ret = idmef_reference_new_meaning(reference, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_constant(str, "squid_id");
        ret = idmef_reference_new_name(reference, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_ref(str, LogTags_str[al->cache.code]);
        ret = idmef_web_service_new_http_method(webservice, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_ref(str, method.rawContent());
        ret = AdditionalDataString(alert, "user_agent", al->request->header.getStr(HDR_USER_AGENT));
        if ( ret < 0 )
            goto err;

        ret = AdditionalDataInteger(alert, "Bytes transmitted", al->http.clientReplySz.messageTotal());
        if ( ret < 0 )
            goto err;

        prelude_client_send_idmef(prelude_client, idmef);

        idmef_message_destroy(idmef);
    }

    return;

err:
    if (idmef != NULL)
        idmef_message_destroy(idmef);

    debugs(50, false, prelude_strsource(ret) << " error: " <<prelude_strerror(ret));
    return;
}
#endif
