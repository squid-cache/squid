/*
 * (C) 2002 Guido Serassio <serassio@libero.it>
 * Based on previous work of Francesco Chemolli, Robert Collins and Andrew Doran
 *
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

#ifndef _LIBSSPWIN32_H_
#define _LIBSSPWIN32_H_
#define SECURITY_WIN32
#define NTLM_PACKAGE_NAME "NTLM"
#define NEGOTIATE_PACKAGE_NAME "Negotiate"

#ifdef _SQUID_CYGWIN_
#include <wchar.h>
#define _T(x) TEXT(x)
#else
#include <tchar.h>
#endif
#include <windows.h>
#include <security.h>
#include <sspi.h>

typedef char * SSP_blobP;

#define WINNT_SECURITY_DLL "security.dll"
#define WIN2K_SECURITY_DLL "secur32.dll"

#define SSP_BASIC 1
#define SSP_NTLM 2

#define SSP_MAX_CRED_LEN 848

#define SSP_DEBUG 0

#define SSP_OK 1
#define SSP_ERROR 2

HMODULE LoadSecurityDll(int, char *);
void UnloadSecurityDll(void);
BOOL WINAPI SSP_LogonUser(PTSTR, PTSTR, PTSTR);
BOOL WINAPI SSP_ValidateNTLMCredentials(PVOID, int, char *);
const char * WINAPI SSP_ValidateNegotiateCredentials(PVOID, int, PBOOL, int *, char *);
const char * WINAPI SSP_MakeChallenge(PVOID, int);
const char * WINAPI SSP_MakeNegotiateBlob(PVOID, int, PBOOL, int *, char *);

extern BOOL Use_Unicode;
extern BOOL NTLM_LocalCall;
#endif /* LIBSSPWIN32_H_ */
