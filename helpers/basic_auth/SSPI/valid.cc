/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
  NT_auth -  Version 2.0

  Modified to act as a Squid authenticator module.
  Removed all Pike stuff.
  Returns OK for a successful authentication, or ERR upon error.

  Guido Serassio, Torino - Italy

  Uses code from -
    Antonino Iannella 2000
    Andrew Tridgell 1997
    Richard Sharpe 1996
    Bill Welliver 1999

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

#include "squid.h"
#include "util.h"

/* Check if we try to compile on a Windows Platform */
#if !_SQUID_WINDOWS_
/* NON Windows Platform !!! */
#error NON WINDOWS PLATFORM
#endif

#if _SQUID_CYGWIN_
#include <wchar.h>
#endif
#include "valid.h"

char Default_NTDomain[DNLEN+1] = NTV_DEFAULT_DOMAIN;
const char * errormsg;

const char NTV_SERVER_ERROR_MSG[] = "Internal server errror";
const char NTV_GROUP_ERROR_MSG[] = "User not allowed to use this cache";
const char NTV_LOGON_ERROR_MSG[] = "No such user or wrong password";
const char NTV_VALID_DOMAIN_SEPARATOR[] = "\\/";

/* returns 1 on success, 0 on failure */
int
Valid_Group(char *UserName, char *Group)
{
    int result = FALSE;
    WCHAR wszUserName[256];	// Unicode user name
    WCHAR wszGroup[256];	// Unicode Group

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
