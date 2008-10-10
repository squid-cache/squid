/*
 * mswin_check_ad_group: lookup group membership in a Windows
 * Active Directory domain
 *
 * (C)2008 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * Based on mswin_check_lm_group by Guido Serassio.
 *
 * Dependencies: Windows 2000 SP4 and later.
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
 * Version 1.0
 * 02-05-2008 Guido Serassio
 *              First release, based on mswin_check_lm_group.
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

#include "config.h"
#ifdef _SQUID_CYGWIN_
#include <wchar.h>
int _wcsicmp(const wchar_t *, const wchar_t *);
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#undef assert
#include <assert.h>
#include <windows.h>
#include <lm.h>
#include <dsgetdc.h>
#include <dsrole.h>

#include "util.h"

#define BUFSIZE 8192		/* the stdin buffer size */
int use_global = 0;
char debug_enabled = 0;
char *myname;
pid_t mypid;
char *machinedomain;
int use_case_insensitive_compare = 0;
char *DefaultDomain = NULL;
const char NTV_VALID_DOMAIN_SEPARATOR[] = "\\/";

#include "mswin_check_ad_group.h"


char *
GetDomainName(void)
{
    static char *DomainName = NULL;
    PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDSRoleInfo;
    DWORD netret;

    if ((netret = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE *) & pDSRoleInfo) == ERROR_SUCCESS)) {
        /*
         * Check the machine role.
         */

        if ((pDSRoleInfo->MachineRole == DsRole_RoleMemberWorkstation) ||
                (pDSRoleInfo->MachineRole == DsRole_RoleMemberServer) ||
                (pDSRoleInfo->MachineRole == DsRole_RoleBackupDomainController) ||
                (pDSRoleInfo->MachineRole == DsRole_RolePrimaryDomainController)) {

            size_t len = wcslen(pDSRoleInfo->DomainNameFlat);

            /* allocate buffer for str + null termination */
            safe_free(DomainName);
            DomainName = (char *) xmalloc(len + 1);
            if (DomainName == NULL)
                return NULL;

            /* copy unicode buffer */
            WideCharToMultiByte(CP_ACP, 0, pDSRoleInfo->DomainNameFlat, -1, DomainName, len, NULL, NULL);

            /* add null termination */
            DomainName[len] = '\0';

            /*
             * Member of a domain. Display it in debug mode.
             */
            debug("Member of Domain %s\n", DomainName);
            debug("Into forest %S\n", pDSRoleInfo->DomainForestName);

        } else {
            debug("Not a Domain member\n");
        }
    } else
        debug("DsRoleGetPrimaryDomainInformation Error: %ld\n", netret);

    /*
     * Free the allocated memory.
     */
    if (pDSRoleInfo != NULL)
        DsRoleFreeMemory(pDSRoleInfo);

    return DomainName;
}

/* returns 0 on match, -1 if no match */
static int
wcstrcmparray(const wchar_t * str, const char **array)
{
    WCHAR wszGroup[GNLEN + 1];	// Unicode Group

    while (*array) {
        MultiByteToWideChar(CP_ACP, 0, *array,
                            strlen(*array) + 1, wszGroup, sizeof(wszGroup) / sizeof(wszGroup[0]));
        debug("Windows group: %S, Squid group: %S\n", str, wszGroup);
        if ((use_case_insensitive_compare ? _wcsicmp(str, wszGroup) : wcscmp(str, wszGroup)) == 0)
            return 0;
        array++;
    }
    return -1;
}

/* returns 1 on success, 0 on failure */
int
Valid_Local_Groups(char *UserName, const char **Groups)
{
    int result = 0;
    char *Domain_Separator;
    WCHAR wszUserName[UNLEN + 1];	// Unicode user name

    LPLOCALGROUP_USERS_INFO_0 pBuf;
    LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = -1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD i;
    DWORD dwTotalCount = 0;
    LPBYTE pBufTmp = NULL;

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
    nStatus = NetUserGetLocalGroups(NULL,
                                    wszUserName,
                                    dwLevel,
                                    dwFlags,
                                    &pBufTmp,
                                    dwPrefMaxLen,
                                    &dwEntriesRead,
                                    &dwTotalEntries);
    pBuf = (LPLOCALGROUP_USERS_INFO_0) pBufTmp;
    /*
     * If the call succeeds,
     */
    if (nStatus == NERR_Success) {
        if ((pTmpBuf = pBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; i++) {
                assert(pTmpBuf != NULL);
                if (pTmpBuf == NULL) {
                    result = 0;
                    break;
                }
                if (wcstrcmparray(pTmpBuf->lgrui0_name, Groups) == 0) {
                    result = 1;
                    break;
                }
                pTmpBuf++;
                dwTotalCount++;
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
    WCHAR wszUserName[UNLEN + 1];	// Unicode user name

    WCHAR wszDomainControllerName[UNCLEN + 1];

    char NTDomain[DNLEN + UNLEN + 2];
    char *domain_qualify = NULL;
    char User[UNLEN + 1];
    size_t j;

    LPGROUP_USERS_INFO_0 pUsrBuf = NULL;
    LPGROUP_USERS_INFO_0 pTmpBuf;
    PDOMAIN_CONTROLLER_INFO pDCInfo = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = -1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD i;
    DWORD dwTotalCount = 0;
    LPBYTE pBufTmp = NULL;

    strncpy(NTDomain, UserName, sizeof(NTDomain));

    for (j = 0; j < strlen(NTV_VALID_DOMAIN_SEPARATOR); j++) {
        if ((domain_qualify = strchr(NTDomain, NTV_VALID_DOMAIN_SEPARATOR[j])) != NULL)
            break;
    }
    if (domain_qualify == NULL) {
        strcpy(User, NTDomain);
        strcpy(NTDomain, DefaultDomain);
    } else {
        strcpy(User, domain_qualify + 1);
        domain_qualify[0] = '\0';
        strlwr(NTDomain);
    }

    debug("Valid_Global_Groups: checking group membership of '%s\\%s'.\n", NTDomain, User);

    /* Convert ANSI User Name to Unicode */

    MultiByteToWideChar(CP_ACP, 0, User,
                        strlen(User) + 1, wszUserName,
                        sizeof(wszUserName) / sizeof(wszUserName[0]));

    /* Query AD for a DC */

    if (DsGetDcName(NULL, NTDomain, NULL, NULL, DS_IS_FLAT_NAME | DS_RETURN_FLAT_NAME, &pDCInfo) != NO_ERROR) {
        fprintf(stderr, "%s DsGetDcName() failed.'\n", myname);
        if (pDCInfo != NULL)
            NetApiBufferFree(pDCInfo);
        return result;
    }
    /* Convert ANSI Domain Controller Name to Unicode */

    MultiByteToWideChar(CP_ACP, 0, pDCInfo->DomainControllerName,
                        strlen(pDCInfo->DomainControllerName) + 1, wszDomainControllerName,
                        sizeof(wszDomainControllerName) / sizeof(wszDomainControllerName[0]));

    debug("Using '%S' as DC for '%s' user's domain.\n", wszDomainControllerName, NTDomain);
    debug("DC Active Directory Site is %s\n", pDCInfo->DcSiteName);
    debug("Machine Active Directory Site is %s\n", pDCInfo->ClientSiteName);

    /*
     * Call the NetUserGetGroups function
     * specifying information level 0.
     */
    dwLevel = 0;
    pBufTmp = NULL;
    nStatus = NetUserGetGroups(wszDomainControllerName,
                               wszUserName,
                               dwLevel,
                               &pBufTmp,
                               dwPrefMaxLen,
                               &dwEntriesRead,
                               &dwTotalEntries);
    pUsrBuf = (LPGROUP_USERS_INFO_0) pBufTmp;
    /*
     * If the call succeeds,
     */
    if (nStatus == NERR_Success) {
        if ((pTmpBuf = pUsrBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; i++) {
                assert(pTmpBuf != NULL);
                if (pTmpBuf == NULL) {
                    result = 0;
                    break;
                }
                if (wcstrcmparray(pTmpBuf->grui0_name, Groups) == 0) {
                    result = 1;
                    break;
                }
                pTmpBuf++;
                dwTotalCount++;
            }
        }
    } else {
        result = 0;
        fprintf(stderr, "%s NetUserGetGroups() failed.'\n", myname);
    }
    /*
     * Free the allocated memory.
     */
    if (pUsrBuf != NULL)
        NetApiBufferFree(pUsrBuf);
    if (pDCInfo != NULL)
        NetApiBufferFree((LPVOID) pDCInfo);
    return result;
}

static void
usage(char *program)
{
    fprintf(stderr, "Usage: %s [-D domain][-G][-P][-c][-d][-h]\n"
            " -D    default user Domain\n"
            " -G    enable Domain Global group mode\n"
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
    while (-1 != (opt = getopt(argc, argv, "D:Gcdh"))) {
        switch (opt) {
        case 'D':
            DefaultDomain = xstrndup(optarg, DNLEN + 1);
            strlwr(DefaultDomain);
            break;
        case 'G':
            use_global = 1;
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
            fprintf(stderr, "%s Unknown option: -%c. Exiting\n", myname, opt);
            usage(argv[0]);
            exit(1);
            break;		/* not reached */
        }
    }
    return;
}


int
main(int argc, char *argv[])
{
    char *p;
    char buf[BUFSIZE];
    char *username;
    char *group;
    int err = 0;
    const char *groups[512];
    int n;

    if (argc > 0) {		/* should always be true */
        myname = strrchr(argv[0], '/');
        if (myname == NULL)
            myname = argv[0];
    } else {
        myname = "(unknown)";
    }
    mypid = getpid();

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check Command Line */
    process_options(argc, argv);

    if (use_global) {
        if ((machinedomain = GetDomainName()) == NULL) {
            fprintf(stderr, "%s Can't read machine domain\n", myname);
            exit(1);
        }
        strlwr(machinedomain);
        if (!DefaultDomain)
            DefaultDomain = xstrdup(machinedomain);
    }
    debug("External ACL win32 group helper build " __DATE__ ", " __TIME__
          " starting up...\n");
    if (use_global)
        debug("Domain Global group mode enabled using '%s' as default domain.\n", DefaultDomain);
    if (use_case_insensitive_compare)
        debug("Warning: running in case insensitive mode !!!\n");

    /* Main Loop */
    while (fgets(buf, sizeof(buf), stdin)) {
        if (NULL == strchr(buf, '\n')) {
            /* too large message received.. skip and deny */
            fprintf(stderr, "%s: ERROR: Too large: %s\n", argv[0], buf);
            while (fgets(buf, sizeof(buf), stdin)) {
                fprintf(stderr, "%s: ERROR: Too large..: %s\n", argv[0], buf);
                if (strchr(buf, '\n') != NULL)
                    break;
            }
            goto error;
        }
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';		/* strip \n */
        if ((p = strchr(buf, '\r')) != NULL)
            *p = '\0';		/* strip \r */

        debug("Got '%s' from Squid (length: %d).\n", buf, strlen(buf));

        if (buf[0] == '\0') {
            fprintf(stderr, "Invalid Request\n");
            goto error;
        }
        username = strtok(buf, " ");
        for (n = 0; (group = strtok(NULL, " ")) != NULL; n++) {
            rfc1738_unescape(group);
            groups[n] = group;
        }
        groups[n] = NULL;

        if (NULL == username) {
            fprintf(stderr, "Invalid Request\n");
            goto error;
        }
        rfc1738_unescape(username);

        if ((use_global ? Valid_Global_Groups(username, groups) : Valid_Local_Groups(username, groups))) {
            printf("OK\n");
        } else {
error:
            printf("ERR\n");
        }
        err = 0;
    }
    return 0;
}
