/* UNIX SMBlib NetBIOS implementation
 * 
 * Version 1.0
 * SMBlib Routines
 * 
 * Copyright (C) Richard Sharpe 1996
 * 
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

int SMBlib_errno;
int SMBlib_SMB_Error;
#define SMBLIB_ERRNO
#define uchar unsigned char
#include "util.h"
#include "smblib-priv.h"
#include "smblib.h"
#include "rfcnb-priv.h"
#include "rfcnb.h"
#include "rfcnb-util.h"
#include "smbencrypt.h"

#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>

SMB_State_Types SMBlib_State;

/* Initialize the SMBlib package     */

int
SMB_Init(void)
{

    SMBlib_State = SMB_State_Started;

    signal(SIGPIPE, SIG_IGN);	/* Ignore these ... */

/* If SMBLIB_Instrument is defines, turn on the instrumentation stuff */
#ifdef SMBLIB_INSTRUMENT

    SMBlib_Instrument_Init();

#endif

    return 0;

}

/* SMB_Create: Create a connection structure and return for later use */
/* We have other helper routines to set variables                     */

SMB_Handle_Type
SMB_Create_Con_Handle(void)
{

    SMBlib_errno = SMBlibE_NotImpl;
    return (NULL);

}

/* SMB_Connect_Server: Connect to a server, but don't negotiate protocol */
/* or anything else ...                                                  */

SMB_Handle_Type
SMB_Connect_Server(SMB_Handle_Type Con_Handle,
    char *server, char *NTdomain)
{
    SMB_Handle_Type con;
    char called[80], calling[80], *address;
    int i;

    /* Get a connection structure if one does not exist */

    con = Con_Handle;

    if (Con_Handle == NULL) {

	if ((con = (struct SMB_Connect_Def *) malloc(sizeof(struct SMB_Connect_Def))) == NULL) {


	    SMBlib_errno = SMBlibE_NoSpace;
	    return NULL;
	}
    }
    /* Init some things ... */

    strcpy(con->service, "");
    strcpy(con->username, "");
    strcpy(con->password, "");
    strcpy(con->sock_options, "");
    strcpy(con->address, "");
    strcpy(con->desthost, server);
    strcpy(con->PDomain, NTdomain);
    strcpy(con->OSName, SMBLIB_DEFAULT_OSNAME);
    strcpy(con->LMType, SMBLIB_DEFAULT_LMTYPE);
    con->first_tree = con->last_tree = NULL;

    SMB_Get_My_Name(con->myname, sizeof(con->myname));

    con->port = 0;		/* No port selected */

    /* Get some things we need for the SMB Header */

    con->pid = getpid();
    con->mid = con->pid;	/* This will do for now ... */
    con->uid = 0;		/* Until we have done a logon, no uid ... */
    con->gid = getgid();

    /* Now connect to the remote end, but first upper case the name of the
     * service we are going to call, sine some servers want it in uppercase */

    for (i = 0; i < strlen(server); i++)
	called[i] = xtoupper(server[i]);

    called[strlen(server)] = 0;	/* Make it a string */

    for (i = 0; i < strlen(con->myname); i++)
	calling[i] = xtoupper(con->myname[i]);

    calling[strlen(con->myname)] = 0;	/* Make it a string */

    if (strcmp(con->address, "") == 0)
	address = con->desthost;
    else
	address = con->address;

    con->Trans_Connect = RFCNB_Call(called,
	calling,
	address,		/* Protocol specific */
	con->port);

    /* Did we get one? */

    if (con->Trans_Connect == NULL) {

	if (Con_Handle == NULL) {
	    Con_Handle = NULL;
	    free(con);
	}
	SMBlib_errno = -SMBlibE_CallFailed;
	return NULL;

    }
    return (con);

}

/* SMB_Connect: Connect to the indicated server                       */
/* If Con_Handle == NULL then create a handle and connect, otherwise  */
/* use the handle passed                                              */

const char *SMB_Prots_Restrict[] =
{"PC NETWORK PROGRAM 1.0",
    NULL};


SMB_Handle_Type
SMB_Connect(SMB_Handle_Type Con_Handle,
    SMB_Tree_Handle * tree,
    char *service,
    char *username,
    char *password)
{
    SMB_Handle_Type con;
    char *host, *address;
    char temp[80], called[80], calling[80];
    int i;

    /* Get a connection structure if one does not exist */

    con = Con_Handle;

    if (Con_Handle == NULL) {

	if ((con = (struct SMB_Connect_Def *) malloc(sizeof(struct SMB_Connect_Def))) == NULL) {

	    SMBlib_errno = SMBlibE_NoSpace;
	    return NULL;
	}
    }
    /* Init some things ... */

    strcpy(con->service, service);
    strcpy(con->username, username);
    strcpy(con->password, password);
    strcpy(con->sock_options, "");
    strcpy(con->address, "");
    strcpy(con->PDomain, SMBLIB_DEFAULT_DOMAIN);
    strcpy(con->OSName, SMBLIB_DEFAULT_OSNAME);
    strcpy(con->LMType, SMBLIB_DEFAULT_LMTYPE);
    con->first_tree = con->last_tree = NULL;

    SMB_Get_My_Name(con->myname, sizeof(con->myname));

    con->port = 0;		/* No port selected */

    /* Get some things we need for the SMB Header */

    con->pid = getpid();
    con->mid = con->pid;	/* This will do for now ... */
    con->uid = 0;		/* Until we have done a logon, no uid */
    con->gid = getgid();

    /* Now figure out the host portion of the service */

    strcpy(temp, service);
    /* AI - Added (char *) to stop compiler warnings */
    host = (char *) strtok(temp, "/\\");	/* Separate host name portion */
    strcpy(con->desthost, host);

    /* Now connect to the remote end, but first upper case the name of the
     * service we are going to call, sine some servers want it in uppercase */

    for (i = 0; i < strlen(host); i++)
	called[i] = xtoupper(host[i]);

    called[strlen(host)] = 0;	/* Make it a string */

    for (i = 0; i < strlen(con->myname); i++)
	calling[i] = xtoupper(con->myname[i]);

    calling[strlen(con->myname)] = 0;	/* Make it a string */

    if (strcmp(con->address, "") == 0)
	address = con->desthost;
    else
	address = con->address;

    con->Trans_Connect = RFCNB_Call(called,
	calling,
	address,		/* Protocol specific */
	con->port);

    /* Did we get one? */

    if (con->Trans_Connect == NULL) {

	if (Con_Handle == NULL) {
	    free(con);
	    Con_Handle = NULL;
	}
	SMBlib_errno = -SMBlibE_CallFailed;
	return NULL;

    }
    /* Now, negotiate the protocol */

    if (SMB_Negotiate(con, SMB_Prots_Restrict) < 0) {

	/* Hmmm what should we do here ... We have a connection, but could not
	 * negotiate ...                                                      */

	return NULL;

    }
    /* Now connect to the service ... */

    if ((*tree = SMB_TreeConnect(con, NULL, service, password, "A:")) == NULL) {

	return NULL;

    }
    return (con);

}

/* Logon to the server. That is, do a session setup if we can. We do not do */
/* Unicode yet!                                                             */

int
SMB_Logon_Server(SMB_Handle_Type Con_Handle, char *UserName,
    char *PassWord)
{
    struct RFCNB_Pkt *pkt;
    int param_len, pkt_len, pass_len;
    char *p, pword[128];

    /* First we need a packet etc ... but we need to know what protocol has  */
    /* been negotiated to figure out if we can do it and what SMB format to  */
    /* use ...                                                               */

    if (Con_Handle->protocol < SMB_P_LanMan1) {

	SMBlib_errno = SMBlibE_ProtLow;
	return (SMBlibE_BAD);

    }
    strcpy(pword, PassWord);
#ifdef PAM_SMB_ENC_PASS
    if (Con_Handle->encrypt_passwords) {
	pass_len = 24;
	SMBencrypt((uchar *) PassWord, (uchar *) Con_Handle->Encrypt_Key, (uchar *) pword);
    } else
#endif
	pass_len = strlen(pword);


    /* Now build the correct structure */

    if (Con_Handle->protocol < SMB_P_NT1) {

	param_len = strlen(UserName) + 1 + pass_len + 1 +
	    strlen(Con_Handle->PDomain) + 1 +
	    strlen(Con_Handle->OSName) + 1;

	pkt_len = SMB_ssetpLM_len + param_len;

	pkt = (struct RFCNB_Pkt *) RFCNB_Alloc_Pkt(pkt_len);

	if (pkt == NULL) {

	    SMBlib_errno = SMBlibE_NoSpace;
	    return (SMBlibE_BAD);	/* Should handle the error */

	}
	memset(SMB_Hdr(pkt), 0, SMB_ssetpLM_len);
	SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);	/* Plunk in IDF */
	*(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
	SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle->pid);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle->mid);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle->uid);
	*(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 10;
	*(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = 0xFF;	/* No extra command */
	SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, 0);

	SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mbs_offset, SMBLIB_MAX_XMIT);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mmc_offset, 2);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_vcn_offset, Con_Handle->pid);
	SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_snk_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_pwl_offset, pass_len + 1);
	SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_res_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_bcc_offset, param_len);

	/* Now copy the param strings in with the right stuff */

	p = (char *) (SMB_Hdr(pkt) + SMB_ssetpLM_buf_offset);

	/* Copy  in password, then the rest. Password has a null at end */

	memcpy(p, pword, pass_len);

	p = p + pass_len + 1;

	strcpy(p, UserName);
	p = p + strlen(UserName);
	*p = 0;

	p = p + 1;

	strcpy(p, Con_Handle->PDomain);
	p = p + strlen(Con_Handle->PDomain);
	*p = 0;
	p = p + 1;

	strcpy(p, Con_Handle->OSName);
	p = p + strlen(Con_Handle->OSName);
	*p = 0;

    } else {

	/* We don't admit to UNICODE support ... */

	param_len = strlen(UserName) + 1 + pass_len +
	    strlen(Con_Handle->PDomain) + 1 +
	    strlen(Con_Handle->OSName) + 1 +
	    strlen(Con_Handle->LMType) + 1;

	pkt_len = SMB_ssetpNTLM_len + param_len;

	pkt = (struct RFCNB_Pkt *) RFCNB_Alloc_Pkt(pkt_len);

	if (pkt == NULL) {

	    SMBlib_errno = SMBlibE_NoSpace;
	    return (-1);	/* Should handle the error */

	}
	memset(SMB_Hdr(pkt), 0, SMB_ssetpNTLM_len);
	SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);	/* Plunk in IDF */
	*(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
	SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle->pid);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle->mid);
	SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle->uid);
	*(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 13;
	*(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = 0xFF;	/* No extra command */
	SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, 0);

	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mbs_offset, SMBLIB_MAX_XMIT);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mmc_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_vcn_offset, 0);
	SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_snk_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cipl_offset, pass_len);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cspl_offset, 0);
	SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_res_offset, 0);
	SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cap_offset, 0);
	SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_bcc_offset, param_len);

	/* Now copy the param strings in with the right stuff */

	p = (char *) (SMB_Hdr(pkt) + SMB_ssetpNTLM_buf_offset);

	/* Copy  in password, then the rest. Password has no null at end */

	memcpy(p, pword, pass_len);

	p = p + pass_len;

	strcpy(p, UserName);
	p = p + strlen(UserName);
	*p = 0;

	p = p + 1;

	strcpy(p, Con_Handle->PDomain);
	p = p + strlen(Con_Handle->PDomain);
	*p = 0;
	p = p + 1;

	strcpy(p, Con_Handle->OSName);
	p = p + strlen(Con_Handle->OSName);
	*p = 0;
	p = p + 1;

	strcpy(p, Con_Handle->LMType);
	p = p + strlen(Con_Handle->LMType);
	*p = 0;

    }

    /* Now send it and get a response */

    if (RFCNB_Send(Con_Handle->Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
	fprintf(stderr, "Error sending SessSetupX request\n");
#endif

	RFCNB_Free_Pkt(pkt);
	SMBlib_errno = SMBlibE_SendFailed;
	return (SMBlibE_BAD);

    }
    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle->Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
	fprintf(stderr, "Error receiving response to SessSetupAndX\n");
#endif

	RFCNB_Free_Pkt(pkt);
	SMBlib_errno = SMBlibE_RecvFailed;
	return (SMBlibE_BAD);

    }
    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {	/* Process error */

#ifdef DEBUG
	fprintf(stderr, "SMB_SessSetupAndX failed with errorclass = %i, Error Code = %i\n",
	    CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
	    SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

	SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
	RFCNB_Free_Pkt(pkt);
	SMBlib_errno = SMBlibE_Remote;
	return (SMBlibE_BAD);

    }
#ifdef DEBUG
    fprintf(stderr, "SessSetupAndX response. Action = %i\n",
	SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset));
#endif

    /* Now pick up the UID for future reference ... */

    Con_Handle->uid = SVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset);
    RFCNB_Free_Pkt(pkt);

    return (0);

}


/* Disconnect from the server, and disconnect all tree connects */

int
SMB_Discon(SMB_Handle_Type Con_Handle, BOOL KeepHandle)
{

    /* We just disconnect the connection for now ... */

    RFCNB_Hangup(Con_Handle->Trans_Connect);

    if (!KeepHandle)
	free(Con_Handle);

    return (0);

}
