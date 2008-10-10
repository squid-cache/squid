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
#include <ntsecapi.h>

#include "util.h"

#define BUFSIZE 8192		/* the stdin buffer size */
int use_global = 0;
int use_PDC_only = 0;
char debug_enabled = 0;
char *myname;
pid_t mypid;
char *machinedomain;
int use_case_insensitive_compare = 0;
char *DefaultDomain = NULL;
const char NTV_VALID_DOMAIN_SEPARATOR[] = "\\/";

#include "win32_check_group.h"


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

    WCHAR wszLocalDomain[DNLEN + 1];	// Unicode Local Domain

    WCHAR wszUserDomain[DNLEN + 1];	// Unicode User Domain

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
        fprintf(stderr, "%s NetServerGetInfo() failed.'\n", myname);
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
                fprintf(stderr, "%s Can't find DC for user's domain '%s'\n", myname, NTDomain);
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
    } else {
        fprintf(stderr, "%s Can't find DC for local domain '%s'\n", myname, machinedomain);
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
usage(char *program)
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
    if (use_PDC_only)
        debug("Warning: using only PDCs for group validation !!!\n");

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
