/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   winbind client common code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#include "winbind_nss_config.h"
#include "winbindd_nss.h"
#include "config.h"


/* Global variables.  These are effectively the client state information */

int winbindd_fd = -1;           /* fd for winbindd socket */
static char *excluded_domain;

/* Free a response structure */

void free_response(struct winbindd_response *response)
{
	/* Free any allocated extra_data */

	if (response)
		SAFE_FREE(response->extra_data);
}

/*
  smbd needs to be able to exclude lookups for its own domain
*/
void winbind_exclude_domain(const char *domain)
{
	SAFE_FREE(excluded_domain);
	excluded_domain = strdup(domain);
}


/* Initialise a request structure */

void init_request(struct winbindd_request *request, int request_type)
{
        static char *domain_env;
        static BOOL initialised;

	request->length = sizeof(struct winbindd_request);

	request->cmd = (enum winbindd_cmd)request_type;
	request->pid = getpid();
	request->domain[0] = '\0';

	if (!initialised) {
		initialised = True;
		domain_env = getenv(WINBINDD_DOMAIN_ENV);
	}

	if (domain_env) {
		strncpy(request->domain, domain_env,
			sizeof(request->domain) - 1);
		request->domain[sizeof(request->domain) - 1] = '\0';
	}
}

/* Initialise a response structure */

void init_response(struct winbindd_response *response)
{
	/* Initialise return value */

	response->result = WINBINDD_ERROR;
}

/* Close established socket */

void close_sock(void)
{
	if (winbindd_fd != -1) {
		close(winbindd_fd);
		winbindd_fd = -1;
	}
}

/* Connect to winbindd socket */

int winbind_open_pipe_sock(void)
{
	struct sockaddr_un sunaddr;
	static pid_t our_pid;
	struct stat st;
	pstring path;
	
	if (our_pid != getpid()) {
		close_sock();
		our_pid = getpid();
	}
	
	if (winbindd_fd != -1) {
		return winbindd_fd;
	}
	
	/* Check permissions on unix socket directory */
	
	if (lstat(WINBINDD_SOCKET_DIR, &st) == -1) {
		return -1;
	}
	
	if (!S_ISDIR(st.st_mode) || 
	    (st.st_uid != 0 && st.st_uid != geteuid())) {
		return -1;
	}
	
	/* Connect to socket */
	
	strncpy(path, WINBINDD_SOCKET_DIR, sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	
	strncat(path, "/", sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	
	strncat(path, WINBINDD_SOCKET_NAME, sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	
	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path) - 1);
	
	/* If socket file doesn't exist, don't bother trying to connect
	   with retry.  This is an attempt to make the system usable when
	   the winbindd daemon is not running. */

	if (lstat(path, &st) == -1) {
		return -1;
	}
	
	/* Check permissions on unix socket file */
	
	if (!S_ISSOCK(st.st_mode) || 
	    (st.st_uid != 0 && st.st_uid != geteuid())) {
		return -1;
	}
	
	/* Connect to socket */
	
	if ((winbindd_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}
	
	if (connect(winbindd_fd, (struct sockaddr *)&sunaddr, 
		    sizeof(sunaddr)) == -1) {
		close_sock();
		return -1;
	}
        
	return winbindd_fd;
}

/* Write data to winbindd socket with timeout */

int write_sock(void *buffer, int count)
{
	int result, nwritten;
	
	/* Open connection to winbind daemon */
	
 restart:
	
	if (winbind_open_pipe_sock() == -1) {
		return -1;
	}
	
	/* Write data to socket */
	
	nwritten = 0;
	
	while(nwritten < count) {
		struct timeval tv;
		fd_set r_fds;
		
		/* Catch pipe close on other end by checking if a read()
		   call would not block by calling select(). */

		FD_ZERO(&r_fds);
		FD_SET(winbindd_fd, &r_fds);
		ZERO_STRUCT(tv);
		
		if (select(winbindd_fd + 1, &r_fds, NULL, NULL, &tv) == -1) {
			close_sock();
			return -1;                   /* Select error */
		}
		
		/* Write should be OK if fd not available for reading */
		
		if (!FD_ISSET(winbindd_fd, &r_fds)) {
			
			/* Do the write */
			
			result = write(winbindd_fd,
				       (char *)buffer + nwritten, 
				       count - nwritten);
			
			if ((result == -1) || (result == 0)) {
				
				/* Write failed */
				
				close_sock();
				return -1;
			}
			
			nwritten += result;
			
		} else {
			
			/* Pipe has closed on remote end */
			
			close_sock();
			goto restart;
		}
	}
	
	return nwritten;
}

/* Read data from winbindd socket with timeout */

static int read_sock(void *buffer, int count)
{
	int result = 0, nread = 0;

	/* Read data from socket */
	
	while(nread < count) {
		
		result = read(winbindd_fd, (char *)buffer + nread, 
			      count - nread);
		
		if ((result == -1) || (result == 0)) {
			
			/* Read failed.  I think the only useful thing we
			   can do here is just return -1 and fail since the
			   transaction has failed half way through. */
			
			close_sock();
			return -1;
		}
		
		nread += result;
	}
	
	return result;
}

/* Read reply */

int read_reply(struct winbindd_response *response)
{
	int result1, result2 = 0;

	if (!response) {
		return -1;
	}
	
	/* Read fixed length response */
	
	if ((result1 = read_sock(response, sizeof(struct winbindd_response)))
	    == -1) {
		
		return -1;
	}
	
	/* We actually send the pointer value of the extra_data field from
	   the server.  This has no meaning in the client's address space
	   so we clear it out. */

	response->extra_data = NULL;

	/* Read variable length response */
	
	if (response->length > sizeof(struct winbindd_response)) {
		int extra_data_len = response->length - 
			sizeof(struct winbindd_response);
		
		/* Mallocate memory for extra data */
		
		if (!(response->extra_data = malloc(extra_data_len))) {
			return -1;
		}
		
		if ((result2 = read_sock(response->extra_data, extra_data_len))
		    == -1) {
			free_response(response);
			return -1;
		}
	}
	
	/* Return total amount of data read */
	
	return result1 + result2;
}

/* 
 * send simple types of requests 
 */

NSS_STATUS winbindd_send_request(int req_type, struct winbindd_request *request)
{
	struct winbindd_request lrequest;

	/* Check for our tricky environment variable */

	if (getenv(WINBINDD_DONT_ENV)) {
		return NSS_STATUS_NOTFOUND;
	}

	/* smbd may have excluded this domain */
	if (excluded_domain && 
	    strcasecmp(excluded_domain, request->domain) == 0) {
		return NSS_STATUS_NOTFOUND;
	}

	if (!request) {
		ZERO_STRUCT(lrequest);
		request = &lrequest;
	}
	
	/* Fill in request and send down pipe */

	init_request(request, req_type);
	
	if (write_sock(request, sizeof(*request)) == -1) {
		return NSS_STATUS_UNAVAIL;
	}
	
	return NSS_STATUS_SUCCESS;
}

/*
 * Get results from winbindd request
 */

NSS_STATUS winbindd_get_response(struct winbindd_response *response)
{
	struct winbindd_response lresponse;

	if (!response) {
		ZERO_STRUCT(lresponse);
		response = &lresponse;
	}

	init_response(response);

	/* Wait for reply */
	if (read_reply(response) == -1) {
		return NSS_STATUS_UNAVAIL;
	}

	/* Throw away extra data if client didn't request it */
	if (response == &lresponse) {
		free_response(response);
	}

	/* Copy reply data from socket */
	if (response->result != WINBINDD_OK) {
		return NSS_STATUS_NOTFOUND;
	}
	
	return NSS_STATUS_SUCCESS;
}

/* Handle simple types of requests */

NSS_STATUS winbindd_request(int req_type, 
				 struct winbindd_request *request,
				 struct winbindd_response *response)
{
	NSS_STATUS status;

	status = winbindd_send_request(req_type, request);
	if (status != NSS_STATUS_SUCCESS) 
		return(status);
	return winbindd_get_response(response);
}
