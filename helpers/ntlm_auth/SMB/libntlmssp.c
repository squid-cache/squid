/*
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>
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


#include "ntlm.h"
#include "util.h"		/* from Squid */
#include "valid.h"

#if HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "smblib-priv.h"	/* for SMB_Handle_Type */

/* a few forward-declarations. Hackish, but I don't care right now */
SMB_Handle_Type SMB_Connect_Server(SMB_Handle_Type Con_Handle,
    char *server, char *NTdomain);

/* this one is reallllly haackiish. We really should be using anything from smblib-priv.h
 */
static char *SMB_Prots[] =
{"PC NETWORK PROGRAM 1.0",
    "MICROSOFT NETWORKS 1.03",
    "MICROSOFT NETWORKS 3.0",
    "DOS LANMAN1.0",
    "LANMAN1.0",
    "DOS LM1.2X002",
    "LM1.2X002",
    "DOS LANMAN2.1",
    "LANMAN2.1",
    "Samba",
    "NT LM 0.12",
    "NT LANMAN 1.0",
    NULL};

#if 0
int SMB_Discon(SMB_Handle_Type Con_Handle, BOOL KeepHandle);
int SMB_Negotiate(void *Con_Handle, char *Prots[]);
int SMB_Logon_Server(SMB_Handle_Type Con_Handle, char *UserName,
    char *PassWord, char *Domain, int precrypted);
#endif

#ifdef DEBUG
#define debug_dump_ntlmssp_flags dump_ntlmssp_flags
#else /* DEBUG */
#define debug_dump_ntlmssp_flags(X)	/* empty */
#endif /* DEBUG */


static char challenge[NONCE_LEN];
SMB_Handle_Type handle = NULL;

/* Disconnects from the DC. A reconnection will be done upon the next request
 */
void
dc_disconnect()
{
    if (handle != NULL)
	SMB_Discon(handle, 0);
    handle = NULL;
}

int
connectedp()
{
    return (handle != NULL);
}


/* Tries to connect to a DC. Returns 0 on failure, 1 on OK */
int
is_dc_ok(char *domain,
    char *domain_controller)
{
    SMB_Handle_Type h = SMB_Connect_Server(NULL, domain_controller, domain);
    if (h == NULL)
	return 0;
    SMB_Discon(h, 0);
    return 1;
}


/* returns 0 on success, > 0 on failure */
static int
init_challenge(char *domain, char *domain_controller)
{
    int smberr;
    char errstr[100];

    if (handle != NULL) {
	return 0;
    }
    debug("Connecting to server %s domain %s\n", domain_controller, domain);
    handle = SMB_Connect_Server(NULL, domain_controller, domain);
    smberr = SMB_Get_Last_Error();
    SMB_Get_Error_Msg(smberr, errstr, 100);


    if (handle == NULL) {	/* couldn't connect */
	debug("Couldn't connect to SMB Server. Error:%s\n", errstr);
	return 1;
    }
    if (SMB_Negotiate(handle, SMB_Prots) < 0) {		/* An error */
	debug("Error negotiating protocol with SMB Server\n");
	SMB_Discon(handle, 0);
	handle = NULL;
	return 2;
    }
    if (handle->Security == 0) {	/* share-level security, unuseable */
	debug("SMB Server uses share-level security .. we need user sercurity.\n");
	SMB_Discon(handle, 0);
	handle = NULL;
	return 3;
    }
    memcpy(challenge, handle->Encrypt_Key, NONCE_LEN);
    return 0;
}

const char *
make_challenge(char *domain, char *domain_controller)
{
    if (init_challenge(domain, domain_controller) > 0)
	return NULL;
    return ntlm_make_challenge(domain, domain_controller, challenge,
	NONCE_LEN);
}

#define min(A,B) (A<B?A:B)
/* returns NULL on failure, or a pointer to
 * the user's credentials (domain\\username)
 * upon success. WARNING. It's pointing to static storage.
 * In case of problem sets as side-effect ntlm_errno to one of the
 * codes defined in ntlm.h
 */
int ntlm_errno;
static char credentials[1024];	/* we can afford to waste */
char *
ntlm_check_auth(ntlm_authenticate * auth, int auth_length)
{
    int rv, retries = 0;
    char pass[25];
    char *domain = credentials;
    char *user;
    lstring tmp;

    if (handle == NULL) {	/*if null we aren't connected, but it shouldn't happen */
	debug("Weird, we've been disconnected\n");
	ntlm_errno = NTLM_NOT_CONNECTED;
	return NULL;
    }
    /* Authenticating against the NT response doesn't seem to work... */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->lmresponse);
    if (tmp.str == NULL) {
	fprintf(stderr, "No auth at all. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    memcpy(pass, tmp.str, tmp.l);
    pass[25] = '\0';

/*      debug("fetching domain\n"); */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->domain);
    if (tmp.str == NULL) {
	debug("No domain supplied. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    memcpy(domain, tmp.str, tmp.l);
    user = domain + tmp.l;
    *user++ = '\0';

/*      debug("fetching user name\n"); */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->user);
    if (tmp.str == NULL) {
	debug("No username supplied. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    memcpy(user, tmp.str, tmp.l);
    *(user + tmp.l) = '\0';

    debug("checking domain: '%s', user: '%s', pass='%s'\n", domain, user, pass);

    rv = SMB_Logon_Server(handle, user, pass, domain, 1);

    while ((rv == NTLM_BAD_PROTOCOL || rv == NTLM_SERVER_ERROR)
	&& retries < BAD_DC_RETRIES_NUMBER) {
	retries++;
	usleep((unsigned long) 100000);
	rv = SMB_Logon_Server(handle, user, pass, domain, 1);
    }

    debug("\tresult is %d\n", rv);

    if (rv != NTV_NO_ERROR) {	/* failed */
	ntlm_errno = rv;
	return NULL;
    }
    *(user - 1) = '\\';

    debug("credentials: %s\n", credentials);
    return credentials;
}
