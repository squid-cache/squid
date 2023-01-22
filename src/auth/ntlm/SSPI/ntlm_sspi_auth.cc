/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * ntlm_sspi_auth: helper for NTLM Authentication for Squid Cache
 *
 * (C)2002,2005 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * Based on previous work of Francesco Chemolli and Robert Collins.
 *
 * Dependencies: Windows NT4 SP4 and later.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * History:
 *
 * Version 1.22
 * 29-10-2005 Guido Serassio
 *              Updated for Negotiate auth support.
 * Version 1.21
 * 21-02-2004 Guido Serassio
 *              Removed control of use of NTLM NEGOTIATE packet from
 *              command line, now the support is automatic.
 * Version 1.20
 * 30-11-2003 Guido Serassio
 *              Added support for NTLM local calls.
 *              Added control of use of NTLM NEGOTIATE packet from
 *              command line.
 *              Updated documentation.
 * Version 1.10
 * 07-09-2003 Guido Serassio
 *              Now is true NTLM authenticator.
 *              More debug info.
 *              Updated documentation.
 * Version 1.0
 * 29-06-2002 Guido Serassio
 *              First release.
 *
 *
 */

/************* CONFIGURATION ***************/

#define FAIL_DEBUG 0

/************* END CONFIGURATION ***************/

//typedef unsigned char uchar;

#include "squid.h"
#include "base64.h"
#include "helper/protocol_defines.h"
#include "ntlmauth/ntlmauth.h"
#include "ntlmauth/support_bits.cci"
#include "sspwin32.h"
#include "util.h"

#include <windows.h>
#include <sspi.h>
#include <security.h>
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <lm.h>
#include <ntsecapi.h>

int NTLM_packet_debug_enabled = 0;
static int have_challenge;
char * NTAllowedGroup;
char * NTDisAllowedGroup;
int UseDisallowedGroup = 0;
int UseAllowedGroup = 0;

#if FAIL_DEBUG
int fail_debug_enabled = 0;
#endif

/* returns 1 on success, 0 on failure */
int
Valid_Group(char *UserName, char *Group)
{
    int result = FALSE;
    WCHAR wszUserName[UNLEN+1]; // Unicode user name
    WCHAR wszGroup[GNLEN+1];    // Unicode Group

    LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
    LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = -1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD i;
    DWORD dwTotalCount = 0;

    /* Convert ANSI User Name and Group to Unicode */

    MultiByteToWideChar(CP_ACP, 0, UserName,
                        strlen(UserName) + 1, wszUserName,
                        sizeof(wszUserName) / sizeof(wszUserName[0]));
    MultiByteToWideChar(CP_ACP, 0, Group,
                        strlen(Group) + 1, wszGroup, sizeof(wszGroup) / sizeof(wszGroup[0]));

    /*
     * Call the NetUserGetLocalGroups function
     * specifying information level 0.
     *
     * The LG_INCLUDE_INDIRECT flag specifies that the
     * function should also return the names of the local
     * groups in which the user is indirectly a member.
     */
    nStatus = NetUserGetLocalGroups(NULL,
                                    wszUserName,
                                    dwLevel,
                                    dwFlags,
                                    (LPBYTE *) & pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);
    /*
     * If the call succeeds,
     */
    if (nStatus == NERR_Success) {
        if ((pTmpBuf = pBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; ++i) {
                if (pTmpBuf == NULL) {
                    result = FALSE;
                    break;
                }
                if (wcscmp(pTmpBuf->lgrui0_name, wszGroup) == 0) {
                    result = TRUE;
                    break;
                }
                ++pTmpBuf;
                ++dwTotalCount;
            }
        }
    } else
        result = FALSE;
    /*
     * Free the allocated memory.
     */
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    return result;
}

char * AllocStrFromLSAStr(LSA_UNICODE_STRING LsaStr)
{
    size_t len;
    static char * target;

    len = LsaStr.Length/sizeof(WCHAR) + 1;

    /* allocate buffer for str + null termination */
    safe_free(target);
    target = (char *)xmalloc(len);
    if (target == NULL)
        return NULL;

    /* copy unicode buffer */
    WideCharToMultiByte(CP_ACP, 0, LsaStr.Buffer, LsaStr.Length, target, len, NULL, NULL );

    /* add null termination */
    target[len-1] = '\0';
    return target;
}

char * GetDomainName(void)

{
    LSA_HANDLE PolicyHandle;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS status;
    PPOLICY_PRIMARY_DOMAIN_INFO ppdiDomainInfo;
    PWKSTA_INFO_100 pwkiWorkstationInfo;
    DWORD netret;
    char * DomainName = NULL;

    /*
     * Always initialize the object attributes to all zeroes.
     */
    memset(&ObjectAttributes, '\0', sizeof(ObjectAttributes));

    /*
     * You need the local workstation name. Use NetWkstaGetInfo at level
     * 100 to retrieve a WKSTA_INFO_100 structure.
     *
     * The wki100_computername field contains a pointer to a UNICODE
     * string containing the local computer name.
     */
    netret = NetWkstaGetInfo(NULL, 100, (LPBYTE *)&pwkiWorkstationInfo);
    if (netret == NERR_Success) {
        /*
         * We have the workstation name in:
         * pwkiWorkstationInfo->wki100_computername
         *
         * Next, open the policy object for the local system using
         * the LsaOpenPolicy function.
         */
        status = LsaOpenPolicy(
                     NULL,
                     &ObjectAttributes,
                     GENERIC_READ | POLICY_VIEW_LOCAL_INFORMATION,
                     &PolicyHandle
                 );

        /*
         * Error checking.
         */
        if (status) {
            debug("OpenPolicy Error: %ld\n", status);
        } else {

            /*
             * You have a handle to the policy object. Now, get the
             * domain information using LsaQueryInformationPolicy.
             */
            status = LsaQueryInformationPolicy(PolicyHandle,
                                               PolicyPrimaryDomainInformation,
                                               (void **)&ppdiDomainInfo);
            if (status) {
                debug("LsaQueryInformationPolicy Error: %ld\n", status);
            } else  {

                /* Get name in usable format */
                DomainName = AllocStrFromLSAStr(ppdiDomainInfo->Name);

                /*
                 * Check the Sid pointer, if it is null, the
                 * workstation is either a stand-alone computer
                 * or a member of a workgroup.
                 */
                if (ppdiDomainInfo->Sid) {

                    /*
                     * Member of a domain. Display it in debug mode.
                     */
                    debug("Member of Domain %s\n",DomainName);
                } else {
                    DomainName = NULL;
                }
            }
        }

        /*
         * Clean up all the memory buffers created by the LSA and
         * Net* APIs.
         */
        NetApiBufferFree(pwkiWorkstationInfo);
        LsaFreeMemory((LPVOID)ppdiDomainInfo);
    } else
        debug("NetWkstaGetInfo Error: %ld\n", netret);
    return DomainName;
}

/*
 * Fills auth with the user's credentials.
 *
 * In case of problem returns one of the
 * codes defined in libntlmauth/ntlmauth.h
 */
int
ntlm_check_auth(ntlm_authenticate * auth, char *user, char *domain, int auth_length)
{
    int x;
    int rv;
    char credentials[DNLEN+UNLEN+2];    /* we can afford to waste */

    if (!NTLM_LocalCall) {

        user[0] = '\0';
        domain[0] = '\0';
        x = ntlm_unpack_auth(auth, user, domain, auth_length);

        if (x != NTLM_ERR_NONE)
            return x;

        if (domain[0] == '\0') {
            debug("No domain supplied. Returning no-auth\n");
            return NTLM_BAD_REQUEST;
        }
        if (user[0] == '\0') {
            debug("No username supplied. Returning no-auth\n");
            return NTLM_BAD_REQUEST;
        }
        debug("checking domain: '%s', user: '%s'\n", domain, user);

    } else
        debug("checking local user\n");

    snprintf(credentials, DNLEN+UNLEN+2, "%s\\%s", domain, user);

    rv = SSP_ValidateNTLMCredentials(auth, auth_length, credentials);

    debug("Login attempt had result %d\n", rv);

    if (!rv) {          /* failed */
        return NTLM_SSPI_ERROR;
    }

    if (UseAllowedGroup) {
        if (!Valid_Group(credentials, NTAllowedGroup)) {
            debug("User %s not in allowed Group %s\n", credentials, NTAllowedGroup);
            return NTLM_BAD_NTGROUP;
        }
    }
    if (UseDisallowedGroup) {
        if (Valid_Group(credentials, NTDisAllowedGroup)) {
            debug("User %s is in denied Group %s\n", credentials, NTDisAllowedGroup);
            return NTLM_BAD_NTGROUP;
        }
    }

    debug("credentials: %s\n", credentials);
    return NTLM_ERR_NONE;
}

void
helperfail(const char *reason)
{
#if FAIL_DEBUG
    fail_debug_enabled =1;
#endif
    SEND_BH(reason);
}

/*
  options:
  -d enable debugging.
  -v enable verbose NTLM packet debugging.
  -A can specify a Windows Local Group name allowed to authenticate.
  -D can specify a Windows Local Group name not allowed to authenticate.
 */
char *my_program_name = NULL;

void
usage()
{
    fprintf(stderr,
            "Usage: %s [-d] [-v] [-A|D LocalUserGroup] [-h]\n"
            " -d  enable debugging.\n"
            " -v  enable verbose NTLM packet debugging.\n"
            " -A  specify a Windows Local Group name allowed to authenticate\n"
            " -D  specify a Windows Local Group name not allowed to authenticate\n"
            " -h  this message\n\n",
            my_program_name);
}

void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr =0;
    while (-1 != (opt = getopt(argc, argv, "hdvA:D:"))) {
        switch (opt) {
        case 'A':
            safe_free(NTAllowedGroup);
            NTAllowedGroup=xstrdup(optarg);
            UseAllowedGroup = 1;
            break;
        case 'D':
            safe_free(NTDisAllowedGroup);
            NTDisAllowedGroup=xstrdup(optarg);
            UseDisallowedGroup = 1;
            break;
        case 'd':
            debug_enabled = 1;
            break;
        case 'v':
            debug_enabled = 1;
            NTLM_packet_debug_enabled = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '?':
            opt = optopt;
            [[fallthrough]];
        default:
            fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
            usage();
            had_error = 1;
        }
    }
    if (had_error)
        exit(EXIT_FAILURE);
}

static bool
token_decode(size_t *decodedLen, uint8_t decoded[], const char *buf)
{
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);
    if (!base64_decode_update(&ctx, decodedLen, decoded, strlen(buf), buf) ||
            !base64_decode_final(&ctx)) {
        SEND_BH("message=\"base64 decode failed\"");
        fprintf(stderr, "ERROR: base64 decoding failed for: '%s'\n", buf);
        return false;
    }
    return true;
}

int
manage_request()
{
    ntlmhdr *fast_header;
    char buf[HELPER_INPUT_BUFFER];
    uint8_t decoded[HELPER_INPUT_BUFFER];
    size_t decodedLen = 0;
    char helper_command[3];
    int oversized = 0;
    char * ErrorMessage;
    static ntlm_negotiate local_nego;
    char domain[DNLEN+1];
    char user[UNLEN+1];

    /* NP: for some reason this helper sometimes needs to accept
     * from clients that send no negotiate packet. */
    if (memcpy(local_nego.hdr.signature, "NTLMSSP", 8) != 0) {
        memset(&local_nego, 0, sizeof(ntlm_negotiate)); /* reset */
        memcpy(local_nego.hdr.signature, "NTLMSSP", 8);     /* set the signature */
        local_nego.hdr.type = le32toh(NTLM_NEGOTIATE);      /* this is a challenge */
        local_nego.flags = le32toh(NTLM_NEGOTIATE_ALWAYS_SIGN |
                                   NTLM_NEGOTIATE_USE_NTLM |
                                   NTLM_NEGOTIATE_USE_LM |
                                   NTLM_NEGOTIATE_ASCII );
    }

    do {
        if (fgets(buf, sizeof(buf), stdin) == NULL)
            return 0;

        char *c = static_cast<char*>(memchr(buf, '\n', sizeof(buf)));
        if (c) {
            if (oversized) {
                helperfail("message=\"illegal request received\"");
                fprintf(stderr, "Illegal request received: '%s'\n", buf);
                return 1;
            }
            *c = '\0';
        } else {
            fprintf(stderr, "No newline in '%s'\n", buf);
            oversized = 1;
            continue;
        }
    } while (false);

    if ((strlen(buf) > 3) && NTLM_packet_debug_enabled) {
        if (!token_decode(&decodedLen, decoded, buf+3))
            return 1;
        strncpy(helper_command, buf, 2);
        debug("Got '%s' from Squid with data:\n", helper_command);
        hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
    } else
        debug("Got '%s' from Squid\n", buf);
    if (memcmp(buf, "YR", 2) == 0) {    /* refresh-request */
        /* figure out what we got */
        if (strlen(buf) > 3) {
            if (!decodedLen /* already decoded*/ && !token_decode(&decodedLen, decoded, buf+3))
                return 1;
        } else {
            debug("Negotiate packet not supplied - self generated\n");
            memcpy(decoded, &local_nego, sizeof(local_nego));
            decodedLen = sizeof(local_nego);
        }
        if ((size_t)decodedLen < sizeof(ntlmhdr)) {     /* decoding failure, return error */
            SEND_ERR("message=\"Packet format error\"");
            return 1;
        }
        /* fast-track-decode request type. */
        fast_header = (struct _ntlmhdr *) decoded;

        /* sanity-check: it IS a NTLMSSP packet, isn't it? */
        if (ntlm_validate_packet(fast_header, NTLM_ANY) != NTLM_ERR_NONE) {
            SEND_ERR("message=\"Broken authentication packet\"");
            return 1;
        }
        switch (fast_header->type) {
        case NTLM_NEGOTIATE: {
            /* Obtain challenge against SSPI */
            debug("attempting SSPI challenge retrieval\n");
            char *c = (char *) SSP_MakeChallenge((ntlm_negotiate *) decoded, decodedLen);
            if (c) {
                SEND_TT(c);
                if (NTLM_packet_debug_enabled) {
                    if (!token_decode(&decodedLen, decoded, c))
                        return 1;
                    debug("send 'TT' to squid with data:\n");
                    hex_dump(reinterpret_cast<unsigned char*>(decoded), decodedLen);
                    if (NTLM_LocalCall) {
                        debug("NTLM Local Call detected\n");
                    }
                }
                have_challenge = 1;
            } else
                helperfail("message=\"can't obtain challenge\"");

            return 1;
        }
        /* notreached */
        case NTLM_CHALLENGE:
            SEND_ERR("message=\"Got a challenge. We refuse to have our authority disputed\"");
            return 1;
        /* notreached */
        case NTLM_AUTHENTICATE:
            SEND_ERR("message=\"Got authentication request instead of negotiate request\"");
            return 1;
        /* notreached */
        default:
            helperfail("message=\"unknown refresh-request packet type\"");
            return 1;
        }
        return 1;
    }
    if (memcmp(buf, "KK ", 3) == 0) {   /* authenticate-request */
        if (!have_challenge) {
            helperfail("message=\"invalid challenge\"");
            return 1;
        }
        /* figure out what we got */
        if (!decodedLen /* already decoded*/ && !token_decode(&decodedLen, decoded, buf+3))
            return 1;

        if ((size_t)decodedLen < sizeof(ntlmhdr)) {     /* decoding failure, return error */
            SEND_ERR("message=\"Packet format error\"");
            return 1;
        }
        /* fast-track-decode request type. */
        fast_header = (struct _ntlmhdr *) decoded;

        /* sanity-check: it IS a NTLMSSP packet, isn't it? */
        if (ntlm_validate_packet(fast_header, NTLM_ANY) != NTLM_ERR_NONE) {
            SEND_ERR("message=\"Broken authentication packet\"");
            return 1;
        }
        switch (fast_header->type) {
        case NTLM_NEGOTIATE:
            SEND_ERR("message=\"Invalid negotiation request received\"");
            return 1;
        /* notreached */
        case NTLM_CHALLENGE:
            SEND_ERR("message=\"Got a challenge. We refuse to have our authority disputed\"");
            return 1;
        /* notreached */
        case NTLM_AUTHENTICATE: {
            /* check against SSPI */
            int err = ntlm_check_auth((ntlm_authenticate *) decoded, user, domain, decodedLen);
            have_challenge = 0;
            if (err != NTLM_ERR_NONE) {
#if FAIL_DEBUG
                fail_debug_enabled =1;
#endif
                switch (err) {
                case NTLM_ERR_NONE:
                    break;
                case NTLM_BAD_NTGROUP:
                    SEND_ERR("message=\"Incorrect Group Membership\"");
                    return 1;
                case NTLM_BAD_REQUEST:
                    SEND_ERR("message=\"Incorrect Request Format\"");
                    return 1;
                case NTLM_SSPI_ERROR:
                    FormatMessage(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        GetLastError(),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                        (LPTSTR) &ErrorMessage,
                        0,
                        NULL);
                    if (ErrorMessage[strlen(ErrorMessage) - 1] == '\n')
                        ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
                    if (ErrorMessage[strlen(ErrorMessage) - 1] == '\r')
                        ErrorMessage[strlen(ErrorMessage) - 1] = '\0';
                    SEND_ERR(ErrorMessage); // TODO update to new syntax
                    LocalFree(ErrorMessage);
                    return 1;
                default:
                    SEND_ERR("message=\"Unknown Error\"");
                    return 1;
                }
            }
            /* let's lowercase them for our convenience */
            lc(domain);
            lc(user);
            fprintf(stdout, "OK user=\"%s\\%s\"", domain, user);
            return 1;
        }
        default:
            helperfail("message=\"unknown authentication packet type\"");
            return 1;
        }
        return 1;
    } else {    /* not an auth-request */
        helperfail("message=\"illegal request received\"");
        fprintf(stderr, "Illegal request received: '%s'\n", buf);
        return 1;
    }
    helperfail("message=\"detected protocol error\"");
    return 1;
    /********* END ********/
}

int
main(int argc, char *argv[])
{
    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s " VERSION " " SQUID_BUILD_INFO " starting up...\n", my_program_name);

    if (LoadSecurityDll(SSP_NTLM, NTLM_PACKAGE_NAME) == NULL) {
        fprintf(stderr, "FATAL, can't initialize SSPI, exiting.\n");
        exit(EXIT_FAILURE);
    }
    debug("SSPI initialized OK\n");

    atexit(UnloadSecurityDll);

    /* initialize FDescs */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (manage_request()) {
        /* everything is done within manage_request */
    }
    return EXIT_SUCCESS;
}

