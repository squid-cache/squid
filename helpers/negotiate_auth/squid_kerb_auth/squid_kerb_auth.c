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
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */
/*
 * Hosted at http://sourceforge.net/projects/squidkerbauth
 */
#include "ska_config.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif


#if !defined(HAVE_DECL_XGETADDRINFO) || !HAVE_DECL_XGETADDRINFO
#define xgetaddrinfo    getaddrinfo
#endif
#if !defined(HAVE_DECL_XFREEADDRINFO) || !HAVE_DECL_XFREEADDRINFO
#define xfreeaddrinfo   freeaddrinfo
#endif
#if !defined(HAVE_DECL_XGAI_STRERROR) || !HAVE_DECL_XGAI_STRERROR
#define xgai_strerror   gai_strerror
#endif
#if !defined(HAVE_DECL_XGETNAMEINFO) || !HAVE_DECL_XGETNAMEINFO
#define xgetnameinfo    getnameinfo
#endif
#if !defined(HAVE_DECL_XMALLOC) || !HAVE_DECL_XMALLOC
#define xmalloc	malloc
#endif
#if !defined(HAVE_DECL_XSTRDUP) || !HAVE_DECL_XSTRDUP
#define xstrdup strdup
#endif
#if !defined(HAVE_DECL_XFREE) || !HAVE_DECL_XFREE
#define xfree free
#endif

#include "base64.h"

#define PROGRAM "squid_kerb_auth"


#ifndef MAX_AUTHTOKEN_LEN
#define MAX_AUTHTOKEN_LEN   65535
#endif

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function, int debug, int log);
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
        tm = localtime((time_t *)&now.tv_sec);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

char *gethost_name(void)
{
    char      hostname[sysconf(_SC_HOST_NAME_MAX)];
    struct addrinfo *hres=NULL, *hres_list;
    int rc,count;

    rc = gethostname(hostname,sysconf(_SC_HOST_NAME_MAX));
    if (rc) {
        fprintf(stderr, "%s| %s: error while resolving hostname '%s'\n", LogTime(), PROGRAM, hostname);
        return NULL;
    }
    rc = xgetaddrinfo(hostname,NULL,NULL,&hres);
    if (rc != 0) {
        fprintf(stderr, "%s| %s: error while resolving hostname with getaddrinfo: %s\n", LogTime(), PROGRAM, xgai_strerror(rc));
        return NULL;
    }
    hres_list=hres;
    count=0;
    while (hres_list) {
        count++;
        hres_list=hres_list->ai_next;
    }
    rc = xgetnameinfo (hres->ai_addr, hres->ai_addrlen,hostname, sizeof (hostname), NULL, 0, 0);
    if (rc != 0) {
        fprintf(stderr, "%s| %s: error while resolving ip address with getnameinfo: %s\n", LogTime(), PROGRAM, xgai_strerror(rc));
        xfreeaddrinfo(hres);
        return NULL ;
    }

    xfreeaddrinfo(hres);
    hostname[sysconf(_SC_HOST_NAME_MAX)-1]='\0';
    return(xstrdup(hostname));
}

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char* function, int debug, int log)
{
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
        fprintf(stdout, "BH %s failed: %s\n",function, buf);
        if (log)
            fprintf(stderr, "%s| %s: User not authenticated\n", LogTime(), PROGRAM);
        return(1);
    }
    return(0);
}



int main(int argc, char * const argv[])
{
    char buf[MAX_AUTHTOKEN_LEN];
    char *c;
    char *user=NULL;
    int length=0;
    static int err=0;
    int opt, debug=0, log=0;
    OM_uint32 ret_flags=0, spnego_flag=0;
    char *service_name=(char *)"HTTP",*host_name=NULL;
    char *token = NULL;
    char *service_principal = NULL;
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t 		gss_context = GSS_C_NO_CONTEXT;
    gss_name_t 		client_name = GSS_C_NO_NAME;
    gss_name_t 		server_name = GSS_C_NO_NAME;
    gss_cred_id_t 	server_creds = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc 	service = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc 	input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc 	output_token = GSS_C_EMPTY_BUFFER;
    const unsigned char	*kerberosToken       = NULL;
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
            log = 1;
            break;
        case 's':
            service_principal = xstrdup(optarg);
            break;
        case 'h':
            fprintf(stderr, "Usage: \n");
            fprintf(stderr, "squid_kerb_auth [-d] [-i] [-s SPN] [-h]\n");
            fprintf(stderr, "-d full debug\n");
            fprintf(stderr, "-i informational messages\n");
            fprintf(stderr, "-s service principal name\n");
            fprintf(stderr, "-h help\n");
            fprintf(stderr, "The SPN can be set to GSS_C_NO_NAME to allow any entry from keytab\n");
            fprintf(stderr, "default SPN is HTTP/fqdn@DEFAULT_REALM\n");
            exit(0);
        default:
            fprintf(stderr, "%s| %s: unknown option: -%c.\n", LogTime(), PROGRAM, opt);
        }
    }

    if (debug)
        fprintf(stderr, "%s| %s: Starting version %s\n", LogTime(), PROGRAM, VERSION);
    if (service_principal && strcasecmp(service_principal,"GSS_C_NO_NAME") ) {
        service.value = service_principal;
        service.length = strlen((char *)service.value);
    } else {
        host_name=gethost_name();
        if ( !host_name ) {
            fprintf(stderr, "%s| %s: Local hostname could not be determined. Please specify the service principal\n", LogTime(), PROGRAM);
            fprintf(stdout, "BH hostname error\n");
            exit(-1);
        }
        service.value = xmalloc(strlen(service_name)+strlen(host_name)+2);
        snprintf(service.value,strlen(service_name)+strlen(host_name)+2,"%s@%s",service_name,host_name);
        service.length = strlen((char *)service.value);
    }

    while (1) {
        if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
            if (ferror(stdin)) {
                if (debug)
                    fprintf(stderr, "%s| %s: fgets() failed! dying..... errno=%d (%s)\n", LogTime(), PROGRAM, ferror(stdin),
                            strerror(ferror(stdin)));

                fprintf(stdout, "BH input error\n");
                exit(1);    /* BIIG buffer */
            }
            fprintf(stdout, "BH input error\n");
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
            fprintf(stdout, "BH Oversized message\n");
            err = 0;
            continue;
        }

        if (debug)
            fprintf(stderr, "%s| %s: Got '%s' from squid (length: %d).\n", LogTime(), PROGRAM, buf,length);

        if (buf[0] == '\0') {
            if (debug)
                fprintf(stderr, "%s| %s: Invalid request\n", LogTime(), PROGRAM);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }

        if (strlen(buf) < 2) {
            if (debug)
                fprintf(stderr, "%s| %s: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }

        if ( !strncmp(buf, "QQ", 2) ) {
            gss_release_buffer(&minor_status, &input_token);
            gss_release_buffer(&minor_status, &output_token);
            gss_release_buffer(&minor_status, &service);
            gss_release_cred(&minor_status, &server_creds);
            if (server_name)
                gss_release_name(&minor_status, &server_name);
            if (client_name)
                gss_release_name(&minor_status, &client_name);
            if (gss_context != GSS_C_NO_CONTEXT )
                gss_delete_sec_context(&minor_status, &gss_context, NULL);
            if (kerberosToken) {
                /* Allocated by parseNegTokenInit, but no matching free function exists.. */
                if (!spnego_flag)
                    xfree((char *)kerberosToken);
                kerberosToken=NULL;
            }
            if (spnego_flag) {
                /* Allocated by makeNegTokenTarg, but no matching free function exists.. */
                if (spnegoToken)
                    xfree((char *)spnegoToken);
                spnegoToken=NULL;
            }
            if (token) {
                xfree(token);
                token=NULL;
            }
            if (host_name) {
                xfree(host_name);
                host_name=NULL;
            }
            fprintf(stdout, "BH quit command\n");
            exit(0);
        }

        if ( strncmp(buf, "YR", 2) && strncmp(buf, "KK", 2) ) {
            if (debug)
                fprintf(stderr, "%s| %s: Invalid request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid request\n");
            continue;
        }
        if ( !strncmp(buf, "YR", 2) ) {
            if (gss_context != GSS_C_NO_CONTEXT )
                gss_delete_sec_context(&minor_status, &gss_context, NULL);
            gss_context = GSS_C_NO_CONTEXT;
        }

        if (strlen(buf) <= 3) {
            if (debug)
                fprintf(stderr, "%s| %s: Invalid negotiate request [%s]\n", LogTime(), PROGRAM, buf);
            fprintf(stdout, "BH Invalid negotiate request\n");
            continue;
        }

        input_token.length = ska_base64_decode_len(buf+3);
        if (debug)
            fprintf(stderr, "%s| %s: Decode '%s' (decoded length: %d).\n", LogTime(), PROGRAM, buf+3,(int)input_token.length);
        input_token.value = xmalloc(input_token.length);

        ska_base64_decode(input_token.value,buf+3,input_token.length);


        if ((input_token.length >= sizeof ntlmProtocol + 1) &&
                (!memcmp (input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
            if (debug)
                fprintf(stderr, "%s| %s: received type %d NTLM token\n", LogTime(), PROGRAM, (int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
            fprintf(stdout, "BH received type %d NTLM token\n",(int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
            goto cleanup;
        }

        if ( service_principal ) {
            if ( strcasecmp(service_principal,"GSS_C_NO_NAME") ) {
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

        if ( check_gss_err(major_status,minor_status,"gss_import_name()",debug,log) )
            goto cleanup;

        major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
                                        GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds,
                                        NULL, NULL);
        if (check_gss_err(major_status,minor_status,"gss_acquire_cred()",debug,log) )
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
                                              NULL);


        if (output_token.length) {
            spnegoToken = output_token.value;
            spnegoTokenLength = output_token.length;
            token = xmalloc(ska_base64_encode_len(spnegoTokenLength));
            if (token == NULL) {
                if (debug)
                    fprintf(stderr, "%s| %s: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }

            ska_base64_encode(token,(const char *)spnegoToken,ska_base64_encode_len(spnegoTokenLength),spnegoTokenLength);

            if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug,log) )
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

            if (check_gss_err(major_status,minor_status,"gss_display_name()",debug,log) )
                goto cleanup;
            user=xmalloc(output_token.length+1);
            if (user == NULL) {
                if (debug)
                    fprintf(stderr, "%s| %s: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }
            memcpy(user,output_token.value,output_token.length);
            user[output_token.length]='\0';
            fprintf(stdout, "AF %s %s\n",token,user);
            if (debug)
                fprintf(stderr, "%s| %s: AF %s %s\n", LogTime(), PROGRAM, token,user);
            if (log)
                fprintf(stderr, "%s| %s: User %s authenticated\n", LogTime(), PROGRAM, user);
            goto cleanup;
        } else {
            if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug,log) )
                goto cleanup;
            if (major_status & GSS_S_CONTINUE_NEEDED) {
                if (debug)
                    fprintf(stderr, "%s| %s: continuation needed\n", LogTime(), PROGRAM);
                fprintf(stdout, "NA %s\n",token);
                goto cleanup;
            }
            gss_release_buffer(&minor_status, &output_token);
            major_status = gss_display_name(&minor_status, client_name, &output_token,
                                            NULL);

            if (check_gss_err(major_status,minor_status,"gss_display_name()",debug,log) )
                goto cleanup;
            /*
             *  Return dummy token AA. May need an extra return tag then AF
             */
            user=xmalloc(output_token.length+1);
            if (user == NULL) {
                if (debug)
                    fprintf(stderr, "%s| %s: Not enough memory\n", LogTime(), PROGRAM);
                fprintf(stdout, "BH Not enough memory\n");
                goto cleanup;
            }
            memcpy(user,output_token.value,output_token.length);
            user[output_token.length]='\0';
            fprintf(stdout, "AF %s %s\n","AA==",user);
            if (debug)
                fprintf(stderr, "%s| %s: AF %s %s\n", LogTime(), PROGRAM, "AA==", user);
            if (log)
                fprintf(stderr, "%s| %s: User %s authenticated\n", LogTime(), PROGRAM, user);

cleanup:
            gss_release_buffer(&minor_status, &input_token);
            gss_release_buffer(&minor_status, &output_token);
            gss_release_cred(&minor_status, &server_creds);
            if (server_name)
                gss_release_name(&minor_status, &server_name);
            if (client_name)
                gss_release_name(&minor_status, &client_name);
            if (kerberosToken) {
                /* Allocated by parseNegTokenInit, but no matching free function exists.. */
                if (!spnego_flag)
                    xfree((char *)kerberosToken);
                kerberosToken=NULL;
            }
            if (spnego_flag) {
                /* Allocated by makeNegTokenTarg, but no matching free function exists.. */
                if (spnegoToken)
                    xfree((char *)spnegoToken);
                spnegoToken=NULL;
            }
            if (token) {
                xfree(token);
                token=NULL;
            }
            if (user) {
                xfree(user);
                user=NULL;
            }
            continue;
        }
    }
}
