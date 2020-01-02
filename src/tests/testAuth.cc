/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_AUTH

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "ConfigParser.h"
#include "testAuth.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testAuth );
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthConfig );
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthUserRequest );
#if HAVE_AUTH_MODULE_BASIC
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthBasicUserRequest );
#endif
#if HAVE_AUTH_MODULE_DIGEST
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthDigestUserRequest );
#endif
#if HAVE_AUTH_MODULE_NTLM
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthNTLMUserRequest );
#endif
#if HAVE_AUTH_MODULE_NEGOTIATE
CPPUNIT_TEST_SUITE_REGISTRATION( testAuthNegotiateUserRequest );
#endif

/* Instantiate all auth framework types */
void
testAuth::instantiate()
{}

char const * stub_config="auth_param digest program /home/robertc/install/squid/libexec/digest_pw_auth /home/robertc/install/squid/etc/digest.pwd\n"
                         "auth_param digest children 5\n"
                         "auth_param digest realm Squid proxy-caching web server\n"
                         "auth_param digest nonce_garbage_interval 5 minutes\n"
                         "auth_param digest nonce_max_duration 30 minutes\n"
                         "auth_param digest nonce_max_count 50\n";

static
char const *
find_proxy_auth(char const *type)
{
    char const * proxy_auths[][2]= { {"basic","Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},

        {"digest", "Digest username=\"robertdig\", realm=\"Squid proxy-caching web server\", nonce=\"yy8rQXjEWwixXVBj\", uri=\"/images/bg8.gif\", response=\"f75a7d3edd48d93c681c75dc4fb58700\", qop=auth, nc=00000012, cnonce=\"e2216641961e228e\" "},
        {"ntlm", "NTLM "},
        {"negotiate", "Negotiate "}
    };

    for (unsigned count = 0; count < 4 ; ++count) {
        if (strcasecmp(type, proxy_auths[count][0]) == 0)
            return proxy_auths[count][1];
    }

    return NULL;
}

static
Auth::Config *
getConfig(char const *type_str)
{
    Auth::ConfigVector &config = Auth::TheConfig;
    /* find a configuration for the scheme */
    Auth::Config *scheme = Auth::Config::Find(type_str);

    if (scheme == NULL) {
        /* Create a configuration */
        Auth::Scheme::Pointer theScheme = Auth::Scheme::Find(type_str);

        if (theScheme == NULL) {
            return NULL;
            //fatalf("Unknown authentication scheme '%s'.\n", type_str);
        }

        config.push_back(theScheme->createConfig());
        scheme = config.back();
        assert(scheme);
    }

    return scheme;
}

static
void
setup_scheme(Auth::Config *scheme, char const **params, unsigned param_count)
{
    Auth::ConfigVector &config = Auth::TheConfig;

    for (unsigned position=0; position < param_count; ++position) {
        char *param_str=xstrdup(params[position]);
        strtok(param_str, w_space);
        ConfigParser::SetCfgLine(strtok(NULL, ""));
        scheme->parse(scheme, config.size(), param_str);
    }
}

static
void
fake_auth_setup()
{
    static bool setup(false);

    if (setup)
        return;

    Mem::Init();

    Auth::ConfigVector &config = Auth::TheConfig;

    char const *digest_parms[]= {"program /home/robertc/install/squid/libexec/digest_pw_auth /home/robertc/install/squid/etc/digest.pwd",
                                 "realm foo"
                                };

    char const *basic_parms[]= {"program /home/robertc/install/squid/libexec/digest_pw_auth /home/robertc/install/squid/etc/digest.pwd",
                                "realm foo"
                               };

    char const *ntlm_parms[]= {"program /home/robertc/install/squid/libexec/digest_pw_auth /home/robertc/install/squid/etc/digest.pwd"};

    char const *negotiate_parms[]= {"program /home/robertc/install/squid/libexec/digest_pw_auth /home/robertc/install/squid/etc/digest.pwd"};

    struct _scheme_params {
        char const *name;
        char const **params;
        unsigned paramlength;
    }

    params[]= { {"digest", digest_parms, 2},
        {"basic", basic_parms, 2},
        {"ntlm", ntlm_parms, 1},
        {"negotiate", negotiate_parms, 1}
    };

    for (unsigned scheme=0; scheme < 4; ++scheme) {
        Auth::Config *schemeConfig;
        schemeConfig = getConfig(params[scheme].name);
        if (schemeConfig != NULL)
            setup_scheme(schemeConfig, params[scheme].params,
                         params[scheme].paramlength);
        else
            fprintf(stderr,"Skipping unknown authentication scheme '%s'.\n",
                    params[scheme].name);
    }

    authenticateInit(&config);

    setup=true;
}

/* Auth::Config::CreateAuthUser works for all
 * authentication types
 */
void
testAuthConfig::create()
{
    Debug::Levels[29]=9;
    fake_auth_setup();

    for (Auth::Scheme::iterator i = Auth::Scheme::GetSchemes().begin(); i != Auth::Scheme::GetSchemes().end(); ++i) {
        AuthUserRequest::Pointer authRequest = Auth::Config::CreateAuthUser(find_proxy_auth((*i)->type()));
        CPPUNIT_ASSERT(authRequest != NULL);
    }
}

#include <iostream>

/* AuthUserRequest::scheme returns the correct scheme for all
 * authentication types
 */
void
testAuthUserRequest::scheme()
{
    Debug::Levels[29]=9;
    fake_auth_setup();

    for (Auth::Scheme::iterator i = Auth::Scheme::GetSchemes().begin(); i != Auth::Scheme::GetSchemes().end(); ++i) {
        // create a user request
        // check its scheme matches *i
        AuthUserRequest::Pointer authRequest = Auth::Config::CreateAuthUser(find_proxy_auth((*i)->type()));
        CPPUNIT_ASSERT_EQUAL(authRequest->scheme(), *i);
    }
}

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/User.h"
#include "auth/basic/UserRequest.h"
/* AuthBasicUserRequest::AuthBasicUserRequest works
 */
void
testAuthBasicUserRequest::construction()
{
    AuthBasicUserRequest();
    AuthBasicUserRequest *temp=new AuthBasicUserRequest();
    delete temp;
}

void
testAuthBasicUserRequest::username()
{
    AuthUserRequest::Pointer temp = new AuthBasicUserRequest();
    Auth::Basic::User *basic_auth=new Auth::Basic::User(Auth::Config::Find("basic"));
    basic_auth->username("John");
    temp->user(basic_auth);
    CPPUNIT_ASSERT_EQUAL(0, strcmp("John", temp->username()));
}
#endif /* HAVE_AUTH_MODULE_BASIC */

#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/User.h"
#include "auth/digest/UserRequest.h"
/* AuthDigestUserRequest::AuthDigestUserRequest works
 */
void
testAuthDigestUserRequest::construction()
{
    AuthDigestUserRequest();
    AuthDigestUserRequest *temp=new AuthDigestUserRequest();
    delete temp;
}

void
testAuthDigestUserRequest::username()
{
    AuthUserRequest::Pointer temp = new AuthDigestUserRequest();
    Auth::Digest::User *duser=new Auth::Digest::User(Auth::Config::Find("digest"));
    duser->username("John");
    temp->user(duser);
    CPPUNIT_ASSERT_EQUAL(0, strcmp("John", temp->username()));
}
#endif /* HAVE_AUTH_MODULE_DIGEST */

#if HAVE_AUTH_MODULE_NTLM
#include "auth/ntlm/User.h"
#include "auth/ntlm/UserRequest.h"
/* AuthNTLMUserRequest::AuthNTLMUserRequest works
 */
void
testAuthNTLMUserRequest::construction()
{
    AuthNTLMUserRequest();
    AuthNTLMUserRequest *temp=new AuthNTLMUserRequest();
    delete temp;
}

void
testAuthNTLMUserRequest::username()
{
    AuthUserRequest::Pointer temp = new AuthNTLMUserRequest();
    Auth::Ntlm::User *nuser=new Auth::Ntlm::User(Auth::Config::Find("ntlm"));
    nuser->username("John");
    temp->user(nuser);
    CPPUNIT_ASSERT_EQUAL(0, strcmp("John", temp->username()));
}
#endif /* HAVE_AUTH_MODULE_NTLM */

#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/User.h"
#include "auth/negotiate/UserRequest.h"
/* AuthNegotiateUserRequest::AuthNegotiateUserRequest works
 */
void
testAuthNegotiateUserRequest::construction()
{
    AuthNegotiateUserRequest();
    AuthNegotiateUserRequest *temp=new AuthNegotiateUserRequest();
    delete temp;
}

void
testAuthNegotiateUserRequest::username()
{
    AuthUserRequest::Pointer temp = new AuthNegotiateUserRequest();
    Auth::Negotiate::User *nuser=new Auth::Negotiate::User(Auth::Config::Find("negotiate"));
    nuser->username("John");
    temp->user(nuser);
    CPPUNIT_ASSERT_EQUAL(0, strcmp("John", temp->username()));
}

#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
#endif /* USE_AUTH */

