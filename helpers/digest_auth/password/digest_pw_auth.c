/*
 * digest_pw_auth.c
 *
 * AUTHOR: Robert Collins. Based on ncsa_auth.c by Arjan de Vet
 * <Arjan.deVet@adv.iae.nl>
 * LDAP backend extension by Flavio Pescuma, MARA Systems AB <flavio@marasystems.com>
 *
 * Example digest authentication program for Squid, based on the original
 * proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>.
 *
 * - comment lines are possible and should start with a '#';
 * - empty or blank lines are possible;
 * - file format is username:password
 *
 * To build a directory integrated backend, you need to be able to
 * calculate the HA1 returned to squid. To avoid storing a plaintext
 * password you can calculate MD5(username:realm:password) when the
 * user changes their password, and store the tuple username:realm:HA1.
 * then find the matching username:realm when squid asks for the
 * HA1.
 *
 * This implementation could be improved by using such a triple for
 * the file format.  However storing such a triple does little to
 * improve security: If compromised the username:realm:HA1 combination
 * is "plaintext equivalent" - for the purposes of digest authentication
 * they allow the user access. Password syncronisation is not tackled
 * by digest - just preventing on the wire compromise.
 *
 * Copyright (c) 2003  Robert Collins  <robertc@squid-cache.org>
 */

#include "digest_common.h"
#include "text_backend.h"
#define PROGRAM_NAME "digest_pw_auth"

static void
GetHHA1(RequestData * requestData)
{
    TextHHA1(requestData);
}

static void
ParseBuffer(char *buf, RequestData * requestData)
{
    char *p;
    requestData->parsed = 0;
    if ((p = strchr(buf, '\n')) != NULL)
        *p = '\0';		/* strip \n */
    if ((requestData->user = strtok(buf, "\"")) == NULL)
        return;
    if ((requestData->realm = strtok(NULL, "\"")) == NULL)
        return;
    if ((requestData->realm = strtok(NULL, "\"")) == NULL)
        return;
    requestData->parsed = -1;
}

static void
OutputHHA1(RequestData * requestData)
{
    requestData->error = 0;
    GetHHA1(requestData);
    if (requestData->error) {
        printf("ERR No such user\n");
        return;
    }
    printf("%s\n", requestData->HHA1);
}

static void
DoOneRequest(char *buf)
{
    RequestData requestData;
    ParseBuffer(buf, &requestData);
    if (!requestData.parsed) {
        printf("ERR\n");
        return;
    }
    OutputHHA1(&requestData);
}

static void
ProcessArguments(int argc, char **argv)
{
    TextArguments(argc, argv);
}

int
main(int argc, char **argv)
{
    char buf[256];
    setbuf(stdout, NULL);
    ProcessArguments(argc, argv);
    while (fgets(buf, 256, stdin) != NULL)
        DoOneRequest(buf);
    exit(0);
}
