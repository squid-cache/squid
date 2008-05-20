/*
 * (C) 2002, 2005 Guido Serassio <guido.serassio@acmeconsulting.it>
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

#undef debug

/************* CONFIGURATION ***************/
/*
 * define this if you want debugging
 */
#ifndef DEBUG
#define DEBUG
#endif

/************* END CONFIGURATION ***************/

#include <sys/types.h>

#define safe_free(x)	if (x) { free(x); x = NULL; }

/* Debugging stuff */

#ifdef __GNUC__			/* this is really a gcc-ism */
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
static char *__foo;
extern char debug_enabled;
#define debug(X...) if (debug_enabled) { \
                    fprintf(stderr,"%s[%d](%s:%d): ", myname, mypid, \
                    ((__foo=strrchr(__FILE__,'/'))==NULL?__FILE__:__foo+1),\
                    __LINE__);\
                    fprintf(stderr,X); }
#else /* DEBUG */
#define debug(X...)		/* */
#endif /* DEBUG */
#else /* __GNUC__ */
extern char debug_enabled;
static void
debug(char *format,...)
{
#ifdef DEBUG
#ifdef _SQUID_MSWIN_
    if (debug_enabled) {
	va_list args;

	va_start(args, format);
	fprintf(stderr, "%s[%d]: ", myname, mypid);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
    }
#endif /* _SQUID_MSWIN_ */
#endif /* DEBUG */
}
#endif /* __GNUC__ */


/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2(X,Y) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#endif
