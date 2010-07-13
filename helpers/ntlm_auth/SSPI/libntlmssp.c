/*
 * (C) 2002,2005 Guido Serassio <guido.serassio@acmeconsulting.it>
 * Based on previous work of Francesco Chemolli and Robert Collins
 * Distributed freely under the terms of the GNU General Public License,
 * version 2. See the file COPYING for licensing details
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 */

typedef unsigned char uchar;

#include "util.h"
#include "ntlm.h"
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <lm.h>
#include <ntsecapi.h>

/* returns 1 on success, 0 on failure */
int
Valid_Group(char *UserName, char *Group)
{
    int result = FALSE;
    WCHAR wszUserName[UNLEN+1];	// Unicode user name
    WCHAR wszGroup[GNLEN+1];	// Unicode Group

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
            for (i = 0; i < dwEntriesRead; i++) {
                if (pTmpBuf == NULL) {
                    result = FALSE;
                    break;
                }
                if (wcscmp(pTmpBuf->lgrui0_name, wszGroup) == 0) {
                    result = TRUE;
                    break;
                }
                pTmpBuf++;
                dwTotalCount++;
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


int ntlm_errno;


/* returns NULL on failure, or a pointer to
 * the user's credentials (domain\\username)
 * upon success. WARNING. It's pointing to static storage.
 * In case of problem sets as side-effect ntlm_errno to one of the
 * codes defined in ntlm.h
 */
char *
ntlm_check_auth(ntlm_authenticate * auth, int auth_length)
{
    int rv;
    char domain[DNLEN+1];
    char user[UNLEN+1];
    static char credentials[DNLEN+UNLEN+2];	/* we can afford to waste */

    lstring tmp;

    if (!NTLM_LocalCall) {

        tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->domain);

        if (tmp.str == NULL || tmp.l == 0) {
            debug("No domain supplied. Returning no-auth\n");
            ntlm_errno = NTLM_BAD_REQUEST;
            return NULL;
        }
        if (Use_Unicode) {
            /* copy unicode buffer */
            WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) tmp.str, tmp.l, domain, DNLEN, NULL, NULL );
            /* add null termination */
            domain[tmp.l / sizeof(WCHAR)] = '\0';
        } else {
            if (tmp.l > DNLEN) {
                debug("Domain string exceeds %d bytes, rejecting\n", DNLEN);
                ntlm_errno = NTLM_BAD_REQUEST;
                return NULL;
            }
            memcpy(domain, tmp.str, tmp.l);
            domain[tmp.l] = '\0';
        }
        tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->user);
        if (tmp.str == NULL || tmp.l == 0) {
            debug("No username supplied. Returning no-auth\n");
            ntlm_errno = NTLM_BAD_REQUEST;
            return NULL;
        }
        if (Use_Unicode) {
            /* copy unicode buffer */
            WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) tmp.str, tmp.l, user, UNLEN, NULL, NULL );
            /* add null termination */
            user[tmp.l / sizeof(WCHAR)] = '\0';
        } else {
            if (tmp.l > UNLEN) {
                debug("Username string exceeds %d bytes, rejecting\n", UNLEN);
                ntlm_errno = NTLM_BAD_REQUEST;
                return NULL;
            }
            memcpy(user, tmp.str, tmp.l);
            user[tmp.l] = '\0';
        }
        debug("checking domain: '%s', user: '%s'\n", domain, user);

    } else
        debug("checking local user\n");

    rv = SSP_ValidateNTLMCredentials(auth, auth_length, credentials);

    debug("Login attempt had result %d\n", rv);

    if (!rv) {			/* failed */
        ntlm_errno = NTLM_SSPI_ERROR;
        return NULL;
    }

    if (UseAllowedGroup) {
        if (!Valid_Group(credentials, NTAllowedGroup)) {
            ntlm_errno = NTLM_BAD_NTGROUP;
            debug("User %s not in allowed Group %s\n", credentials, NTAllowedGroup);
            return NULL;
        }
    }
    if (UseDisallowedGroup) {
        if (Valid_Group(credentials, NTDisAllowedGroup)) {
            ntlm_errno = NTLM_BAD_NTGROUP;
            debug("User %s is in denied Group %s\n", credentials, NTDisAllowedGroup);
            return NULL;
        }
    }

    debug("credentials: %s\n", credentials);
    return credentials;
}


const char *
ntlm_make_negotiate(void)
{
    ntlm_negotiate ne;
    const char *encoded;
    memset(&ne, 0, sizeof(ntlm_negotiate));	/* reset */
    memcpy(ne.signature, "NTLMSSP", 8);		/* set the signature */
    ne.type = le32toh(NTLM_NEGOTIATE);	/* this is a challenge */
    ne.flags = le32toh(
                   NEGOTIATE_ALWAYS_SIGN |
                   NEGOTIATE_USE_NTLM |
                   NEGOTIATE_USE_LM |
                   NEGOTIATE_ASCII |
                   0
               );
    encoded = base64_encode_bin((char *) &ne, NEGOTIATE_LENGTH);
    debug("Negotiate packet not supplied - self generated\n");
    return encoded;
}


void hex_dump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    if (!data)
        return;

    if (debug_enabled) {
        unsigned char *p = data;
        unsigned char c;
        int n;
        char bytestr[4] = {0};
        char addrstr[10] = {0};
        char hexstr[ 16*3 + 5] = {0};
        char charstr[16*1 + 5] = {0};
        for (n=1; n<=size; n++) {
            if (n%16 == 1) {
                /* store address for this line */
                snprintf(addrstr, sizeof(addrstr), "%.4x",
                         ((unsigned int)p-(unsigned int)data) );
            }

            c = *p;
            if (xisalnum(c) == 0) {
                c = '.';
            }

            /* store hex str (for left side) */
            snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
            strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

            /* store char str (for right side) */
            snprintf(bytestr, sizeof(bytestr), "%c", c);
            strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

            if (n%16 == 0) {
                /* line completed */
                fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
                hexstr[0] = 0;
                charstr[0] = 0;
            } else if (n%8 == 0) {
                /* half line: add whitespaces */
                strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
                strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
            }
            p++; /* next byte */
        }

        if (strlen(hexstr) > 0) {
            /* print rest of buffer if not empty */
            fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
        }
    }
}

