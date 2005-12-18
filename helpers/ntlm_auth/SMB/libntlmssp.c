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

typedef unsigned char uchar;

#include "ntlm.h"
#include "util.h"		/* from Squid */
#include "valid.h"
#include "smbencrypt.h"

#if HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* these are part of rfcnb-priv.h and smblib-priv.h */
extern int SMB_Get_Error_Msg(int msg, char *msgbuf, int len);
extern int SMB_Get_Last_Error();
extern int RFCNB_Get_Last_Errno();

#include "smblib-priv.h"	/* for SMB_Handle_Type */

/* a few forward-declarations. Hackish, but I don't care right now */
SMB_Handle_Type SMB_Connect_Server(SMB_Handle_Type Con_Handle, char *server, char *NTdomain);

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
    NULL
};

#if 0
int SMB_Discon(SMB_Handle_Type Con_Handle, BOOL KeepHandle);
int SMB_Negotiate(void *Con_Handle, char *Prots[]);
int SMB_Logon_Server(SMB_Handle_Type Con_Handle, char *UserName, char *PassWord, char *Domain, int precrypted);
#endif

#ifdef DEBUG
#define debug_dump_ntlmssp_flags dump_ntlmssp_flags
#else /* DEBUG */
#define debug_dump_ntlmssp_flags(X)	/* empty */
#endif /* DEBUG */


#define ENCODED_PASS_LEN 24
static unsigned char challenge[NONCE_LEN];
static unsigned char lmencoded_empty_pass[ENCODED_PASS_LEN],
	ntencoded_empty_pass[ENCODED_PASS_LEN];
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
is_dc_ok(char *domain, char *domain_controller)
{
    SMB_Handle_Type h = SMB_Connect_Server(NULL, domain_controller, domain);
    if (h == NULL)
	return 0;
    SMB_Discon(h, 0);
    return 1;
}


static char errstr[1001];
/* returns 0 on success, > 0 on failure */
static int
init_challenge(char *domain, char *domain_controller)
{
    int smberr;

    if (handle != NULL) {
	return 0;
    }
    debug("Connecting to server %s domain %s\n", domain_controller, domain);
    handle = SMB_Connect_Server(NULL, domain_controller, domain);
    smberr = SMB_Get_Last_Error();
    SMB_Get_Error_Msg(smberr, errstr, 1000);


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
	debug("SMB Server uses share-level security .. we need user security.\n");
	SMB_Discon(handle, 0);
	handle = NULL;
	return 3;
    }
    memcpy(challenge, handle->Encrypt_Key, NONCE_LEN);
		SMBencrypt((unsigned char *)"",challenge,lmencoded_empty_pass);
		SMBNTencrypt((unsigned char *)"",challenge,ntencoded_empty_pass);
    return 0;
}

static char my_domain[100], my_domain_controller[100];
const char *
make_challenge(char *domain, char *domain_controller)
{
	/* trying to circumvent some strange problem wih pointers in SMBLib */
	/* Ugly as hell, but the lib is going to be dropped... */
	strcpy(my_domain,domain);
	strcpy(my_domain_controller,domain_controller);
    if (init_challenge(my_domain, my_domain_controller) > 0) {
	return NULL;
    }
    return ntlm_make_challenge(my_domain, my_domain_controller, (char *)challenge, NONCE_LEN);
}

#define min(A,B) (A<B?A:B)

int ntlm_errno;
#define MAX_USERNAME_LEN 255
#define MAX_DOMAIN_LEN 255
#define MAX_PASSWD_LEN 31
static char credentials[MAX_USERNAME_LEN+MAX_DOMAIN_LEN+2];	/* we can afford to waste */


/* Fetches the user's credentials from the challenge.
 * Returns NULL if domain or user is not defined
 * No identity control is performed.
 * WARNING! The result is static storage, shared with ntlm_check_auth
 */
char *
fetch_credentials(ntlm_authenticate * auth, int auth_length)
{
    char *p = credentials;
    lstring tmp;
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->domain);
    *p = '\0';
    if (tmp.str == NULL)
	return NULL;
    memcpy(p, tmp.str, tmp.l);
    p += tmp.l;
    *p++ = '\\';
    *p = '\0';
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->user);
    if (tmp.str == NULL)
	return NULL;
    memcpy(p, tmp.str, tmp.l);
    *(p + tmp.l) = '\0';
    return credentials;
}

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
    char pass[MAX_PASSWD_LEN+1];
    char *domain = credentials;
    char *user;
    lstring tmp;

    if (handle == NULL) {	/*if null we aren't connected, but it shouldn't happen */
	debug("Weird, we've been disconnected\n");
	ntlm_errno = NTLM_NOT_CONNECTED;
	return NULL;
    }

/*      debug("fetching domain\n"); */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->domain);
    if (tmp.str == NULL || tmp.l == 0) {
	debug("No domain supplied. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    if (tmp.l > MAX_DOMAIN_LEN) {
	debug("Domain string exceeds %d bytes, rejecting\n", MAX_DOMAIN_LEN);
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    memcpy(domain, tmp.str, tmp.l);
    user = domain + tmp.l;
    *user++ = '\0';

/*      debug("fetching user name\n"); */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->user);
    if (tmp.str == NULL || tmp.l == 0) {
	debug("No username supplied. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    if (tmp.l > MAX_USERNAME_LEN) {
	debug("Username string exceeds %d bytes, rejecting\n", MAX_USERNAME_LEN);
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    memcpy(user, tmp.str, tmp.l);
    *(user + tmp.l) = '\0';

		
    /* Authenticating against the NT response doesn't seem to work... */
    tmp = ntlm_fetch_string((char *) auth, auth_length, &auth->lmresponse);
    if (tmp.str == NULL || tmp.l == 0) {
	fprintf(stderr, "No auth at all. Returning no-auth\n");
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }
    if (tmp.l > MAX_PASSWD_LEN) {
	debug("Password string exceeds %d bytes, rejecting\n", MAX_PASSWD_LEN);
	ntlm_errno = NTLM_LOGON_ERROR;
	return NULL;
    }

    memcpy(pass, tmp.str, tmp.l);
    pass[min(MAX_PASSWD_LEN,tmp.l)] = '\0';

#if 1
		debug ("Empty LM pass detection: user: '%s', ours:'%s', his: '%s'"
					 "(length: %d)\n",
					 user,lmencoded_empty_pass,tmp.str,tmp.l);
		if (memcmp(tmp.str,lmencoded_empty_pass,ENCODED_PASS_LEN)==0) {
			fprintf(stderr,"Empty LM password supplied for user %s\\%s. "
							"No-auth\n",domain,user);
			ntlm_errno=NTLM_LOGON_ERROR;
			return NULL;
		}
		
		tmp = ntlm_fetch_string ((char *) auth, auth_length, &auth->ntresponse);
		if (tmp.str != NULL && tmp.l != 0) {
			debug ("Empty NT pass detection: user: '%s', ours:'%s', his: '%s'"
						 "(length: %d)\n",
						 user,ntencoded_empty_pass,tmp.str,tmp.l);
			if (memcmp(tmp.str,lmencoded_empty_pass,ENCODED_PASS_LEN)==0) {
				fprintf(stderr,"Empty NT password supplied for user %s\\%s. "
								"No-auth\n",domain,user);
				ntlm_errno=NTLM_LOGON_ERROR;
				return NULL;
			}
		}
#endif

		/* TODO: check against empty password!!!!! */
		


    debug("checking domain: '%s', user: '%s', pass='%s'\n", domain, user, pass);

    rv = SMB_Logon_Server(handle, user, pass, domain, 1);
    debug("Login attempt had result %d\n", rv);

    if (rv != NTV_NO_ERROR) {	/* failed */
	ntlm_errno = rv;
	return NULL;
    }
    *(user - 1) = '\\';		/* hack. Performing, but ugly. */

    debug("credentials: %s\n", credentials);
    return credentials;
}
