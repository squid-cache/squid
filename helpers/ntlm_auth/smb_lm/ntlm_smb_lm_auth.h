/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>,
 *        inspired by previous work by Andrew Doran <ad@interlude.eu.org>
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

#ifndef _NTLM_H_
#define _NTLM_H_

#include "config.h"
#include "ntlmauth.h"

/* for time_t */
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/************* CONFIGURATION ***************/
/*
 * define this if you want debugging
 */
#ifndef DEBUG
#define DEBUG
#endif

#define DEAD_DC_RETRY_INTERVAL 30

/************* END CONFIGURATION ***************/

#include <sys/types.h>


/* Debugging stuff */

#ifdef __GNUC__			/* this is really a gcc-ism */
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
static const char *__foo;
extern char debug_enabled;
#define debug(X...) if (debug_enabled) { \
                    fprintf(stderr,"ntlm-auth[%ld](%s:%d): ", (long)getpid(), \
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
}

#endif


/* A couple of harmless helper macros */
#define SEND(X) debug("sending '%s' to squid\n",X); printf(X "\n");
#ifdef __GNUC__
#define SEND2(X,Y...) debug("sending '" X "' to squid\n",Y); printf(X "\n",Y);
#else
/* no gcc, no debugging. varargs macros are a gcc extension */
#define SEND2 printf
#endif

extern int ntlm_errno;
#define NTLM_NO_ERROR 0
#define NTLM_SERVER_ERROR 1
#define NTLM_PROTOCOL_ERROR 2
#define NTLM_LOGON_ERROR 3
#define NTLM_UNTRUSTED_DOMAIN 4
#define NTLM_BAD_PROTOCOL -1
#define NTLM_NOT_CONNECTED 10


const char *make_challenge(char *domain, char *controller);
extern char *ntlm_check_auth(ntlm_authenticate * auth, int auth_length);
extern char *fetch_credentials(ntlm_authenticate * auth, int auth_length);
void dc_disconnect(void);
int connectedp(void);
int is_dc_ok(char *domain, char *domain_controller);

typedef struct _dc dc;
struct _dc {
    char *domain;
    char *controller;
    time_t dead;		/* 0 if it's alive, otherwise time of death */
    dc *next;
};


#endif /* _NTLM_H_ */
