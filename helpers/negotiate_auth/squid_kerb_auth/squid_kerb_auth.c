/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * -----------------------------------------------------------------------------
 */
/*
 * Hosted at http://sourceforge.net/projects/squidkerbauth
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "base64.h"
#ifndef HAVE_SPNEGO
#include "spnegohelp.h"
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN HOST_NAME_MAX
#endif

#define PROGRAM "squid_kerb_auth"

#ifdef HEIMDAL
#include <gssapi.h>
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#else
#include <gssapi/gssapi.h>
#ifndef SOLARIS_11
#include <gssapi/gssapi_generic.h>
#else
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#endif
#endif

#include <krb5.h>
int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function, int debug, int loging);
char *gethost_name(void);
static const char *LogTime(void);

static const unsigned char ntlmProtocol [] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

static const char *LogTime()
{
    struct tm *tm;
    struct timeval now;
    static time_t last_t = 0;
    static char buf[128];

    gettimeofday(&now, NULL);
    if (now.tv_sec != last_t) {
        tm = localtime(&now.tv_sec);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

char *gethost_name(void) {
  char      hostname[MAXHOSTNAMELEN];
  struct addrinfo *hres=NULL, *hres_list;
  int rc,count;

  rc = gethostname(hostname,MAXHOSTNAMELEN);
  if (rc)
    {
      fprintf(stderr, "%s| %s: error while resolving hostname '%s'\n", LogTime(), PROGRAM, hostname);
      return NULL;
    }
  rc = getaddrinfo(hostname,NULL,NULL,&hres);
  if (rc != 0) {
    fprintf(stderr, "%s| %s: error while resolving hostname with getaddrinfo: %s\n", LogTime(), PROGRAM, gai_strerror(rc));
    return NULL;
  }
  hres_list=hres;
  count=0;
  while (hres_list) {
    count++;
    hres_list=hres_list->ai_next;
  }
  rc = getnameinfo (hres->ai_addr, hres->ai_addrlen,hostname, sizeof (hostname), NULL, 0, 0);
  if (rc != 0) {
    fprintf(stderr, "%s| %s: error while resolving ip address with getnameinfo: %s\n", LogTime(), PROGRAM, gai_strerror(rc));
    freeaddrinfo(hres);
    return NULL ;
  }

  freeaddrinfo(hres);
  hostname[MAXHOSTNAMELEN]='\0';
  return(strdup(hostname));
}

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function, int debug, int loging) {
  if (GSS_ERROR(major_status)) {
    OM_uint32 maj_stat,min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf[1024];
    size_t len;

    len = 0;
    msg_ctx = 0;
    while (!msg_ctx) {
      /* convert major status code (GSS-API error) to text */
      maj_stat = gss_display_status(&min_stat, major_status,
				    GSS_C_GSS_CODE,
				    GSS_C_NULL_OID,
				    &msg_ctx, &status_string);
      if (maj_stat == GSS_S_COMPLETE) {
	if (sizeof(buf) > len + status_string.length + 1) {
	  sprintf(buf+len, "%s", (char*) status_string.value);
	  len += status_string.length;
	}
	gss_release_buffer(&min_stat, &status_string);
	break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    if (sizeof(buf) > len + 2) {
      sprintf(buf+len, "%s", ". ");
      len += 2;
    }
    msg_ctx = 0;
    while (!msg_ctx) {
      /* convert minor status code (underlying routine error) to text */
      maj_stat = gss_display_status(&min_stat, minor_status,
				    GSS_C_MECH_CODE,
				    GSS_C_NULL_OID,
				    &msg_ctx, &status_string);
      if (maj_stat == GSS_S_COMPLETE) {
	if (sizeof(buf) > len + status_string.length ) {
	  sprintf(buf+len, "%s", (char*) status_string.value);
	  len += status_string.length;
	}
	gss_release_buffer(&min_stat, &status_string);
	break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    if (debug)
      fprintf(stderr, "%s| %s: %s failed: %s\n", LogTime(), PROGRAM, function, buf);
    fprintf(stdout, "NA %s failed: %s\n",function, buf);
    if (loging)
      fprintf(stderr, "%s| %s: User not authenticated\n", LogTime(), PROGRAM);
    return(1);
  }
  return(0);
}



int main(int argc, char * const argv[])
{
  char buf[6400];
  char *c;
  int length=0;
  static int err=0;
  int opt, rc, debug=0, loging=0;
  OM_uint32 ret_flags=0, spnego_flag=0;
  char *service_name=(char *)"HTTP",*host_name=NULL;
  char *token = NULL;
  char *service_principal = NULL;
  OM_uint32 major_status, minor_status;
  gss_ctx_id_t 		gss_context = GSS_C_NO_CONTEXT;
  gss_name_t 		client_name = GSS_C_NO_NAME;
  gss_name_t 		server_name = GSS_C_NO_NAME;
  gss_cred_id_t 	server_creds = GSS_C_NO_CREDENTIAL;
  gss_cred_id_t 	delegated_cred = GSS_C_NO_CREDENTIAL;
  gss_buffer_desc 	service = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc 	input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc 	output_token = GSS_C_EMPTY_BUFFER;
  const unsigned char	*kerberosToken       = NULL;
  size_t		kerberosTokenLength = 0;
  const unsigned char	*spnegoToken         = NULL ;
  size_t		spnegoTokenLength   = 0;

  setbuf(stdout,NULL);
  setbuf(stdin,NULL);

  while (-1 != (opt = getopt(argc, argv, "dis:h"))) {
    switch (opt) {
    case 'd':
      debug = 1;
      break;              
    case 'i':
      loging = 1;
      break;              
    case 's':
      service_principal = strdup(optarg);
      break;
    case 'h':
      fprintf(stdout, "Usage: \n");
      fprintf(stdout, "squid_kerb_auth -d [-s SPN]\n");
      fprintf(stdout, "SPN = service principal name\n");
      fprintf(stdout, "Can be set to GSS_C_NO_NAME to allow any entry from keytab\n");
      fprintf(stdout, "default SPN is HTTP/fqdn@DEFAULT_REALM\n");
      break;
    default:
      fprintf(stderr, "%s| %s: unknown option: -%c.\n", LogTime(), PROGRAM, opt);
    }
  }

  if (service_principal && strcasecmp(service_principal,"GSS_C_NO_NAME") ) {
    service.value = service_principal;
    service.length = strlen((char *)service.value);
  } else {
    host_name=gethost_name();
    if ( !host_name ) {
      fprintf(stderr, "%s| %s: Local hostname could not be determined. Please specify the service principal\n", LogTime(), PROGRAM);
      exit(-1);
    }
    service.value = malloc(strlen(service_name)+strlen(host_name)+2);
    snprintf(service.value,strlen(service_name)+strlen(host_name)+2,"%s@%s",service_name,host_name);
    service.length = strlen((char *)service.value);
  }

  while (1) {
    if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      if (ferror(stdin)) {
	if (debug)
	  fprintf(stderr, "%s| %s: fgets() failed! dying..... errno=%d (%s)\n", LogTime(), PROGRAM, ferror(stdin),
		 strerror(ferror(stdin)));

	exit(1);    /* BIIG buffer */
      }
      exit(0);
    }

    c=memchr(buf,'\n',sizeof(buf)-1);
    if (c) {
      *c = '\0';
      length = c-buf;
    } else {
      err = 1;
    }
    if (err) {
      if (debug)
	fprintf(stderr, "%s| %s: Oversized message\n", LogTime(), PROGRAM);
      fprintf(stdout, "NA Oversized message\n");
      err = 0;
      continue;
    }

    if (debug)
      fprintf(stderr, "%s| %s: Got '%s' from squid (length: %d).\n", LogTime(), PROGRAM, buf?buf:"NULL",length);

    if (buf[0] == '\0') {
      if (debug)
	fprintf(stderr, "%s| %s: Invalid request\n", LogTime(), PROGRAM);
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }

    if (strlen(buf) < 2) {
      if (debug)
	fprintf(stderr, "%s| %s: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }

    if ( !strncmp(buf, "QQ", 2) ) {
      gss_release_buffer(&minor_status, &input_token);
      gss_release_buffer(&minor_status, &output_token);
      gss_release_buffer(&minor_status, &service);
      gss_release_cred(&minor_status, &server_creds);
      gss_release_cred(&minor_status, &delegated_cred);
      gss_release_name(&minor_status, &server_name);
      gss_release_name(&minor_status, &client_name);
      gss_delete_sec_context(&minor_status, &gss_context, NULL);
      if (kerberosToken) {
	/* Allocated by parseNegTokenInit, but no matching free function exists.. */
        if (!spnego_flag)
          free((char *)kerberosToken);
        kerberosToken=NULL;
      }
      if (spnego_flag) {
	/* Allocated by makeNegTokenTarg, but no matching free function exists.. */
        if (spnegoToken) 
	  free((char *)spnegoToken);
      	spnegoToken=NULL;
      }
      if (token) {
        free(token);
        token=NULL;
      }
      if (host_name) {
        free(host_name);
        host_name=NULL;
      }
      exit(0);
    }

    if ( !strncmp(buf, "YR", 2) && !strncmp(buf, "KK", 2) ) {
      if (debug)
	fprintf(stderr, "%s| %s: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }
    if ( !strncmp(buf, "YR", 2) ){
      if (gss_context != GSS_C_NO_CONTEXT )
        gss_delete_sec_context(&minor_status, &gss_context, NULL);
      gss_context = GSS_C_NO_CONTEXT;
    }

    if (strlen(buf) <= 3) {
      if (debug)
	fprintf(stderr, "%s| %s: Invalid negotiate request [%s]\n", LogTime(), PROGRAM, buf);
      fprintf(stdout, "NA Invalid negotiate request\n");
      continue;
    }
        
    input_token.length = base64_decode_len(buf+3);
    input_token.value = malloc(input_token.length);

    base64_decode(input_token.value,buf+3,input_token.length);

 
#ifndef HAVE_SPNEGO
    if (( rc=parseNegTokenInit (input_token.value,
				input_token.length,
				&kerberosToken,
				&kerberosTokenLength))!=0 ){
      if (debug)
	fprintf(stderr, "%s| %s: parseNegTokenInit failed with rc=%d\n", LogTime(), PROGRAM, rc);
        
      /* if between 100 and 200 it might be a GSSAPI token and not a SPNEGO token */    
      if ( rc < 100 || rc > 199 ) {
	if (debug)
	  fprintf(stderr, "%s| %s: Invalid GSS-SPNEGO query [%s]\n", LogTime(), PROGRAM, buf);
	fprintf(stdout, "NA Invalid GSS-SPNEGO query\n");
	goto cleanup;
      } 
      if ((input_token.length >= sizeof ntlmProtocol + 1) &&
	  (!memcmp (input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
	if (debug)
	  fprintf(stderr, "%s| %s: received type %d NTLM token\n", LogTime(), PROGRAM, (int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
	fprintf(stdout, "NA received type %d NTLM token\n",(int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
	goto cleanup;
      } 
      spnego_flag=0;
    } else {
      gss_release_buffer(&minor_status, &input_token);
      input_token.length=kerberosTokenLength;
      input_token.value=(void *)kerberosToken;
      spnego_flag=1;
    }
#else
    if ((input_token.length >= sizeof ntlmProtocol + 1) &&
	(!memcmp (input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
      if (debug)
	fprintf(stderr, "%s| %s: received type %d NTLM token\n", LogTime(), PROGRAM, (int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
      fprintf(stdout, "NA received type %d NTLM token\n",(int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
      goto cleanup;
    } 
#endif
     
    if ( service_principal ) {
      if ( strcasecmp(service_principal,"GSS_C_NO_NAME") ){
        major_status = gss_import_name(&minor_status, &service,
  				       (gss_OID) GSS_C_NULL_OID, &server_name);
       
      } else {
        server_name = GSS_C_NO_NAME;
        major_status = GSS_S_COMPLETE;
      }
    } else {
      major_status = gss_import_name(&minor_status, &service,
  				     gss_nt_service_name, &server_name);
    }

    if ( check_gss_err(major_status,minor_status,"gss_import_name()",debug,loging) )
      goto cleanup;

    major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
				    GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds,
				    NULL, NULL);
    if (check_gss_err(major_status,minor_status,"gss_acquire_cred()",debug,loging) )
      goto cleanup;

    major_status = gss_accept_sec_context(&minor_status,
					  &gss_context,
					  server_creds,
					  &input_token,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &client_name,
					  NULL,
					  &output_token,
					  &ret_flags,
					  NULL,
					  &delegated_cred);


    if (output_token.length) {
#ifndef HAVE_SPNEGO
      if (spnego_flag) {
	if ((rc=makeNegTokenTarg (output_token.value,
				  output_token.length,
				  &spnegoToken,
				  &spnegoTokenLength))!=0 ) {
	  if (debug)
	    fprintf(stderr, "%s| %s: makeNegTokenTarg failed with rc=%d\n", LogTime(), PROGRAM, rc);
	  fprintf(stdout, "NA makeNegTokenTarg failed with rc=%d\n",rc);
	  goto cleanup;
	}
      } else {
	spnegoToken = output_token.value;
	spnegoTokenLength = output_token.length;
      }
#else
      spnegoToken = output_token.value;
      spnegoTokenLength = output_token.length;
#endif
      token = malloc(base64_encode_len(spnegoTokenLength));
      if (token == NULL) {
	if (debug)
	  fprintf(stderr, "%s| %s: Not enough memory\n", LogTime(), PROGRAM);
	fprintf(stdout, "NA Not enough memory\n");
        goto cleanup;
      }

      base64_encode(token,(const char *)spnegoToken,base64_encode_len(spnegoTokenLength),spnegoTokenLength);

      if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug,loging) )
	goto cleanup;
      if (major_status & GSS_S_CONTINUE_NEEDED) {
	if (debug)
	  fprintf(stderr, "%s| %s: continuation needed\n", LogTime(), PROGRAM);
	fprintf(stdout, "TT %s\n",token);
        goto cleanup;
      }
      gss_release_buffer(&minor_status, &output_token);
      major_status = gss_display_name(&minor_status, client_name, &output_token,
				      NULL);

      if (check_gss_err(major_status,minor_status,"gss_display_name()",debug,loging) )
	goto cleanup;
      fprintf(stdout, "AF %s %s\n",token,(char *)output_token.value);
      if (debug)
	fprintf(stderr, "%s| %s: AF %s %s\n", LogTime(), PROGRAM, token,(char *)output_token.value); 
      if (loging)
	fprintf(stderr, "%s| %s: User %s authenticated\n", LogTime(), PROGRAM, (char *)output_token.value);
      goto cleanup;
    } else {
      if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug,loging) )
	goto cleanup;
      if (major_status & GSS_S_CONTINUE_NEEDED) {
	if (debug)
	  fprintf(stderr, "%s| %s: continuation needed\n", LogTime(), PROGRAM);
	fprintf(stdout, "NA No token to return to continue\n");
	goto cleanup;
      }
      gss_release_buffer(&minor_status, &output_token);
      major_status = gss_display_name(&minor_status, client_name, &output_token,
				      NULL);

      if (check_gss_err(major_status,minor_status,"gss_display_name()",debug,loging) )
	goto cleanup;
      /* 
       *  Return dummy token AA. May need an extra return tag then AF
       */
      fprintf(stdout, "AF %s %s\n","AA==",(char *)output_token.value);
      if (debug)
	fprintf(stderr, "%s| %s: AF %s %s\n", LogTime(), PROGRAM, "AA==", (char *)output_token.value);
      if (loging)
	fprintf(stderr, "%s| %s: User %s authenticated\n", LogTime(), PROGRAM, (char *)output_token.value);

cleanup:
      gss_release_buffer(&minor_status, &input_token);
      gss_release_buffer(&minor_status, &output_token);
      gss_release_cred(&minor_status, &server_creds);
      gss_release_cred(&minor_status, &delegated_cred);
      gss_release_name(&minor_status, &server_name);
      gss_release_name(&minor_status, &client_name);
      if (kerberosToken) {
	/* Allocated by parseNegTokenInit, but no matching free function exists.. */
	if (!spnego_flag)
           free((char *)kerberosToken);
      	kerberosToken=NULL;
      }
      if (spnego_flag) {
	/* Allocated by makeNegTokenTarg, but no matching free function exists.. */
        if (spnegoToken)
	  free((char *)spnegoToken);
      	spnegoToken=NULL;
      }
      if (token) {
        free(token);
      	token=NULL;
      }
      continue;            
    }
  }
}
