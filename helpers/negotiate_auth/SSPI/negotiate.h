/*
 * (C) 2005 Guido Serassio <guido.serassio@acmeconsulting.it>
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

#ifndef _NEGOTIATE_H_
#define _NEGOTIATE_H_

#include "sspwin32.h"
#include <windows.h>
#include <sspi.h>
#include <security.h>
#undef debug

/************* CONFIGURATION ***************/
/*
 * define this if you want debugging
 */
#ifndef DEBUG
#define DEBUG
#endif

#define FAIL_DEBUG 0

/************* END CONFIGURATION ***************/

#include <sys/types.h>

extern int debug_enabled;
#if FAIL_DEBUG
extern int fail_debug_enabled;
#endif

/* Debugging stuff */

#ifdef __GNUC__			/* this is really a gcc-ism */
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
static char *__foo;
#define debug(X...) if (debug_enabled) { \
                    fprintf(stderr,"ntlm-auth[%d](%s:%d): ", getpid(), \
                    ((__foo=strrchr(__FILE__,'/'))==NULL?__FILE__:__foo+1),\
                    __LINE__);\
                    fprintf(stderr,X); }
#else /* DEBUG */
#define debug(X...)		/* */
#endif /* DEBUG */
#else /* __GNUC__ */
static void
debug(char *format,...)
{
#ifdef DEBUG
#ifdef _SQUID_MSWIN_
#if FAIL_DEBUG
    if (debug_enabled || fail_debug_enabled) {
#else
if (debug_enabled) {
#endif
        va_list args;

        va_start(args,format);
        fprintf(stderr, "negotiate-auth[%d]: ",getpid());
        vfprintf(stderr, format, args);
        va_end(args);
#if FAIL_DEBUG
        fail_debug_enabled = 0;
#endif
    }
#endif /* _SQUID_MSWIN_ */
#endif /* DEBUG */
}
#endif /* __GNUC__ */


/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#define SEND3(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2(X,Y) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#define SEND3(X,Y,Z) debug("sending '" X "' to squid\n",Y,Z); printf(X "\n",Y,Z);
#endif

extern void uc(char *);

extern char *negotiate_check_auth(SSP_blobP auth, int auth_length);
extern void hex_dump(void *, int);

#define safe_free(x)	if (x) { free(x); x = NULL; }

#endif /* _NEGOTIATE_H_ */
