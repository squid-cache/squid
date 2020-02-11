/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * mswin_check_lm_group: lookup group membership in a Windows NT/2000 domain
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
 * In part based on check_group by Rodrigo Albani de Campos.
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
 * 08-07-2005 Guido Serassio
 *              Added -P option for force usage of PDCs for group validation.
 *              Added support for '/' char as domain separator.
 *              Fixed Bugzilla #1336.
 * Version 1.21
 * 23-04-2005 Guido Serassio
 *              Added -D option for specify default user's domain.
 * Version 1.20.1
 * 15-08-2004 Guido Serassio
 *              Helper protocol changed to use URL escaped strings in Squid-3.0
 *              (Original work of Henrik Nordstrom)
 * Version 1.20
 * 13-06-2004 Guido Serassio
 *              Added support for running on a Domain Controller.
 * Version 1.10
 * 01-05-2003 Guido Serassio
 *              Added option for case insensitive group name comparation.
 *              More debug info.
 *              Updated documentation.
 *              Segfault bug fix (Bugzilla #574)
 * Version 1.0
 * 24-06-2002 Guido Serassio
 *              Using the main function from check_group and sections
 *              from wbinfo wrote win32_group
 *
 * This is a helper for the external ACL interface for Squid Cache
 *
 * It reads from the standard input the domain username and a list of
 * groups and tries to match it against the groups membership of the
 * specified username.
 *
 * Returns `OK' if the user belongs to a group or `ERR' otherwise, as
 * described on http://devel.squid-cache.org/external_acl/config.html
 *
 */

#include "squid.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"
#include "util.h"

#if _SQUID_CYGWIN_
#include <wchar.h>
int _wcsicmp(const wchar_t *, const wchar_t *);
#endif

#undef assert
#include <cassert>
#include <cctype>
#include <cstring>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <windows.h>
#include <lm.h>
#include <ntsecapi.h>

int use_global = 0;
int use_PDC_only = 0;
const char *program_name;
pid_t mypid;
char *machinedomain;
int use_case_insensitive_compare = 0;
char *DefaultDomain = NULL;
const char NTV_VALID_DOMAIN_SEPARATOR[] = "\\/";

char *
AllocStrFromLSAStr(LSA_UNICODE_STRING LsaStr)
{
    size_t len;
    static char *target;

    len = LsaStr.Length / sizeof(WCHAR) + 1;

    /* allocate buffer for str + null termination */
    safe_free(target);
    target = (char *) xmalloc(len);
    if (target == NULL)
        return NULL;

    /* copy unicode buffer */
    WideCharToMultiByte(CP_ACP, 0, LsaStr.Buffer, LsaStr.Length, target, len, NULL, NULL);

    /* add null termination */
    target[len - 1] = '\0';
    return target;
}

char *
GetDomainName(void)
{
    LSA_HANDLE PolicyHandle;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS status;
    PPOLICY_PRIMARY_DOMAIN_INFO ppdiDomainInfo;
    PWKSTA_INFO_100 pwkiWorkstationInfo;
    DWORD netret;
    char *DomainName = NULL;

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
    netret = NetWkstaGetInfo(NULL, 100, (LPBYTE *) & pwkiWorkstationInfo);
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
                                               (PVOID *) & ppdiDomainInfo);
            if (status) {
                debug("LsaQueryInformationPolicy Error: %ld\n", status);
            } else {

                /* Get name in useable format */
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
                    debug("Member of Domain %s\n", DomainName);
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
        LsaFreeMemory((LPVOID) ppdiDomainInfo);
    } else
        debug("NetWkstaGetInfo Error: %ld\n", netret);
    return DomainName;
}

/* returns 0 on match, -1 if no match */
static int
wcstrcmparray(const wchar_t * str, const char **array)
{
    WCHAR wszGroup[GNLEN + 1];  // Unicode Group

    while (*array) {
        MultiByteToWideChar(CP_ACP, 0, *array,
                            strlen(*array) + 1, wszGroup, sizeof(wszGroup) / sizeof(wszGroup[0]));
        debug("Windows group: %S, Squid group: %S\n", str, wszGroup);
        if ((use_case_insensitive_compare ? _wcsicmp(str, wszGroup) : wcscmp(str, wszGroup)) == 0)
            return 0;
        ++array;
    }
    return -1;
}

/* returns 1 on success, 0 on failure */
int
Valid_Local_Groups(char *UserName, const char **Groups)
{
    int result = 0;
    char *Domain_Separator;
    WCHAR wszUserName[UNLEN + 1];   // Unicode user name

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

    if ((Domain_Separator = strchr(UserName, '/')) != NULL)
        *Domain_Separator = '\\';

    debug("Valid_Local_Groups: checking group membership of '%s'.\n", UserName);

    /* Convert ANSI User Name and Group to Unicode */

    MultiByteToWideChar(CP_ACP, 0, UserName,
                        strlen(UserName) + 1, wszUserName, sizeof(wszUserName) / sizeof(wszUserName[0]));

    /*
     * Call the NetUserGetLocalGroups function
     * specifying information level 0.
     *
     * The LG_INCLUDE_INDIRECT flag specifies that the
     * function should also return the names of the local
     * groups in which the user is indirectly a member.
     */
    nStatus = NetUserGetLocalGroups(
                  NULL,
                  wszUserName,
                  dwLevel,
                  dwFlags,
                  (LPBYTE *) & pBuf,
                  dwPrefMaxLen,
                  &dwEntriesRead,
                  &dwTotalEntries);
    /*
     * If the call succeeds,
     */
    if (nStatus == NERR_Success) {
        if ((pTmpBuf = pBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; ++i) {
                assert(pTmpBuf != NULL);
                if (pTmpBuf == NULL) {
                    result = 0;
                    break;
                }
                if (wcstrcmparray(pTmpBuf->lgrui0_name, Groups) == 0) {
                    result = 1;
                    break;
                }
                ++pTmpBuf;
                ++dwTotalCount;
            }
        }
    } else
        result = 0;
    /*
     * Free the allocated memory.
     */
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    return result;
}

/* returns 1 on success, 0 on failure */
int
Valid_Global_Groups(char *UserName, const char **Groups)
{
    int result = 0;
    WCHAR wszUserName[UNLEN + 1];   // Unicode user name

    WCHAR wszLocalDomain[DNLEN + 1];    // Unicode Local Domain

    WCHAR wszUserDomain[DNLEN + 1]; // Unicode User Domain

    char NTDomain[DNLEN + UNLEN + 2];
    char *domain_qualify;
    char User[UNLEN + 1];
    size_t j;

    LPWSTR LclDCptr = NULL;
    LPWSTR UsrDCptr = NULL;
    LPGROUP_USERS_INFO_0 pUsrBuf = NULL;
    LPGROUP_USERS_INFO_0 pTmpBuf;
    LPSERVER_INFO_101 pSrvBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = -1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD i;
    DWORD dwTotalCount = 0;

    strncpy(NTDomain, UserName, sizeof(NTDomain));

    for (j = 0; j < strlen(NTV_VALID_DOMAIN_SEPARATOR); ++j) {
        if ((domain_qualify = strchr(NTDomain, NTV_VALID_DOMAIN_SEPARATOR[j])) != NULL)
            break;
    }
    if (domain_qualify == NULL) {
        xstrncpy(User, NTDomain, sizeof(User));
        xstrncpy(NTDomain, DefaultDomain, sizeof(NTDomain));
    } else {
        xstrncpy(User, domain_qualify + 1, sizeof(User));
        domain_qualify[0] = '\0';
        strlwr(NTDomain);
    }

    debug("Valid_Global_Groups: checking group membership of '%s\\%s'.\n", NTDomain, User);

    /* Convert ANSI User Name and Group to Unicode */

    MultiByteToWideChar(CP_ACP, 0, User,
                        strlen(User) + 1, wszUserName,
                        sizeof(wszUserName) / sizeof(wszUserName[0]));
    MultiByteToWideChar(CP_ACP, 0, machinedomain,
                        strlen(machinedomain) + 1, wszLocalDomain, sizeof(wszLocalDomain) / sizeof(wszLocalDomain[0]));

    /* Call the NetServerGetInfo function for local computer, specifying level 101. */
    dwLevel = 101;
    nStatus = NetServerGetInfo(NULL, dwLevel, (LPBYTE *) & pSrvBuf);

    if (nStatus == NERR_Success) {
        /* Check if we are running on a Domain Controller */
        if ((pSrvBuf->sv101_type & SV_TYPE_DOMAIN_CTRL) ||
                (pSrvBuf->sv101_type & SV_TYPE_DOMAIN_BAKCTRL)) {
            LclDCptr = NULL;
            debug("Running on a DC.\n");
        } else
            nStatus = (use_PDC_only ? NetGetDCName(NULL, wszLocalDomain, (LPBYTE *) & LclDCptr) : NetGetAnyDCName(NULL, wszLocalDomain, (LPBYTE *) & LclDCptr));
    } else {
        fprintf(stderr, "%s: ERROR: NetServerGetInfo() failed.'\n", program_name);
        if (pSrvBuf != NULL)
            NetApiBufferFree(pSrvBuf);
        return result;
    }

    if (nStatus == NERR_Success) {
        debug("Using '%S' as DC for '%S' local domain.\n", LclDCptr, wszLocalDomain);

        if (strcmp(NTDomain, machinedomain) != 0) {
            MultiByteToWideChar(CP_ACP, 0, NTDomain,
                                strlen(NTDomain) + 1, wszUserDomain, sizeof(wszUserDomain) / sizeof(wszUserDomain[0]));
            nStatus = (use_PDC_only ? NetGetDCName(LclDCptr, wszUserDomain, (LPBYTE *) & UsrDCptr) : NetGetAnyDCName(LclDCptr, wszUserDomain, (LPBYTE *) & UsrDCptr));
            if (nStatus != NERR_Success) {
                fprintf(stderr, "%s: ERROR: Can't find DC for user's domain '%s'\n", program_name, NTDomain);
                if (pSrvBuf != NULL)
                    NetApiBufferFree(pSrvBuf);
                if (LclDCptr != NULL)
                    NetApiBufferFree((LPVOID) LclDCptr);
                if (UsrDCptr != NULL)
                    NetApiBufferFree((LPVOID) UsrDCptr);
                return result;
            }
        } else
            UsrDCptr = LclDCptr;

        debug("Using '%S' as DC for '%s' user's domain.\n", UsrDCptr, NTDomain);
        /*
         * Call the NetUserGetGroups function
         * specifying information level 0.
         */
        dwLevel = 0;
        nStatus = NetUserGetGroups(UsrDCptr,
                                   wszUserName,
                                   dwLevel,
                                   (LPBYTE *) & pUsrBuf,
                                   dwPrefMaxLen,
                                   &dwEntriesRead,
                                   &dwTotalEntries);
        /*
         * If the call succeeds,
         */
        if (nStatus == NERR_Success) {
            if ((pTmpBuf = pUsrBuf) != NULL) {
                for (i = 0; i < dwEntriesRead; ++i) {
                    assert(pTmpBuf != NULL);
                    if (pTmpBuf == NULL) {
                        result = 0;
                        break;
                    }
                    if (wcstrcmparray(pTmpBuf->grui0_name, Groups) == 0) {
                        result = 1;
                        break;
                    }
                    ++pTmpBuf;
                    ++dwTotalCount;
                }
            }
        } else {
            result = 0;
            fprintf(stderr, "%s: ERROR: NetUserGetGroups() failed.'\n", program_name);
        }
    } else {
        fprintf(stderr, "%s: ERROR: Can't find DC for local domain '%s'\n", program_name, machinedomain);
    }
    /*
     * Free the allocated memory.
     */
    if (pSrvBuf != NULL)
        NetApiBufferFree(pSrvBuf);
    if (pUsrBuf != NULL)
        NetApiBufferFree(pUsrBuf);
    if ((UsrDCptr != NULL) && (UsrDCptr != LclDCptr))
        NetApiBufferFree((LPVOID) UsrDCptr);
    if (LclDCptr != NULL)
        NetApiBufferFree((LPVOID) LclDCptr);
    return result;
}

static void
usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-D domain][-G][-P][-c][-d][-h]\n"
            " -D    default user Domain\n"
            " -G    enable Domain Global group mode\n"
            " -P    use ONLY PDCs for group validation\n"
            " -c    use case insensitive compare\n"
            " -d    enable debugging\n"
            " -h    this message\n",
            program);
}

void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "D:GPcdh"))) {
        switch (opt) {
        case 'D':
            DefaultDomain = xstrndup(optarg, DNLEN + 1);
            strlwr(DefaultDomain);
            break;
        case 'G':
            use_global = 1;
            break;
        case 'P':
            use_PDC_only = 1;
            break;
        case 'c':
            use_case_insensitive_compare = 1;
            break;
        case 'd':
            debug_enabled = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        case '?':
            opt = optopt;
        /* fall thru to default */
        default:
            fprintf(stderr, "%s: FATAL: Unknown option: -%c. Exiting\n", program_name, opt);
            usage(argv[0]);
            exit(1);
            break;      /* not reached */
        }
    }
    return;
}

int
main(int argc, char *argv[])
{
    char *p;
    char buf[HELPER_INPUT_BUFFER];
    char *username;
    char *group;
    const char *groups[512];
    int n;

    if (argc > 0) {     /* should always be true */
        program_name = strrchr(argv[0], '/');
        if (program_name == NULL)
            program_name = argv[0];
    } else {
        program_name = "(unknown)";
    }
    mypid = getpid();

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check Command Line */
    process_options(argc, argv);

    if (use_global) {
        if ((machinedomain = GetDomainName()) == NULL) {
            fprintf(stderr, "%s: FATAL: Can't read machine domain\n", program_name);
            exit(1);
        }
        strlwr(machinedomain);
        if (!DefaultDomain)
            DefaultDomain = xstrdup(machinedomain);
    }
    debug("%s " VERSION " " SQUID_BUILD_INFO " starting up...\n", argv[0]);
    if (use_global) {
        debug("Domain Global group mode enabled using '%s' as default domain.\n", DefaultDomain);
    }
    if (use_case_insensitive_compare) {
        debug("Warning: running in case insensitive mode !!!\n");
    }
    if (use_PDC_only) {
        debug("Warning: using only PDCs for group validation !!!\n");
    }

    /* Main Loop */
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
        if (NULL == strchr(buf, '\n')) {
            /* too large message received.. skip and deny */
            debug("%s: ERROR: Too large: %s\n", argv[0], buf);
            while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
                debug("%s: ERROR: Too large..: %s\n", argv[0], buf);
                if (strchr(buf, '\n') != NULL)
                    break;
            }
            SEND_BH(HLP_MSG("Input Too Long."));
            continue;
        }
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';      /* strip \n */
        if ((p = strchr(buf, '\r')) != NULL)
            *p = '\0';      /* strip \r */

        debug("Got '%s' from Squid (length: %d).\n", buf, strlen(buf));

        if (buf[0] == '\0') {
            SEND_BH(HLP_MSG("Invalid Request."));
            continue;
        }
        username = strtok(buf, " ");
        for (n = 0; (group = strtok(NULL, " ")) != NULL; ++n) {
            rfc1738_unescape(group);
            groups[n] = group;
        }
        groups[n] = NULL;

        if (NULL == username) {
            SEND_BH(HLP_MSG("Invalid Request. No Username."));
            continue;
        }
        rfc1738_unescape(username);

        if ((use_global ? Valid_Global_Groups(username, groups) : Valid_Local_Groups(username, groups))) {
            SEND_OK("");
        } else {
            SEND_ERR("");
        }
    }
    return 0;
}

