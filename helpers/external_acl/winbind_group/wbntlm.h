/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>,
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

#ifndef _WBNTLM_H_
#define _WBNTLM_H_

#include "config.h"
#include "ntlmauth.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


/*************** CONFIGURATION ***************/
#ifndef DEBUG
#define DEBUG
#endif

/* the attempted entropy source. If it doesn't exist, random() is uesed */
#define ENTROPY_SOURCE "/dev/urandom"

#define DOMAIN "GCSINT"         /* TODO: fix ntlm_make_challenge */

/************* END CONFIGURATION *************/

/* Debugging stuff */
extern const char *myname;
static const char *__foo;
extern pid_t mypid;
extern char debug_enabled;

#ifdef DEBUG
#define __DO_DEBUG 1
#else
#define __DO_DEBUG 0
#endif

#ifdef __GNUC__     /* this is really a gcc-ism */
#define warn(X...)  fprintf(stderr,"%s[%d](%s:%d): ", myname, mypid, \
                    ((__foo=strrchr(__FILE__,'/'))==NULL?__FILE__:__foo+1),\
                    __LINE__);\
                    fprintf(stderr,X)
#define debug(X...) if(__DO_DEBUG && debug_enabled) { warn(X); }
#else /* __GNUC__ */
static void
debug(char *format,...)
{
}
static void
warn(char *format,...)
{
}
#endif /* __GNUC__ */



/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); \
                      printf(X "\n",Y)
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2 printf
#endif

typedef enum {
  YES,
  NO,
  DONTKNOW
} tristate;

#define CHALLENGE_LEN 8
#define BUFFER_SIZE 2010

#endif /* _WBNTLM_H_ */
