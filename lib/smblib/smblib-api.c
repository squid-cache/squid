/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMB API Calls ...

   Copyright (C) Richard Sharpe 1996
*/

/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "squid.h"
#include "rfcnb/rfcnb.h"
#include "smblib/smblib-priv.h"

#if HAVE_STRING_H
#include <string.h>
#endif

SMB_Tree_Handle SMBapi_Tree = NULL;

/* Send an api request to the \\server\IPC$ tree, with a \PIPE\LANMAN api  */
/* request to change the user's password                                   */

#define SMB_LMAPI_SLOT "\\PIPE\\LANMAN"
#define SMB_LMAPI_SUPW_DESC "zb16b16WW"

int SMBapi_NetUserPasswordSet(SMB_Tree_Handle tree, char *user,
                              char *oldpass, char *newpass, int *apiStatus)

{
    struct RFCNB_Pkt *pkt;
    int param_len, i, pkt_len, pad_api_name = FALSE;
    char *p;

    /* Get a packet, we need one with space for a transact plus. The calc   */
    /* below lays it all out as it is, including the empty string after the */
    /* descriptor and before the username                                   */

    param_len = 2 + strlen(SMB_LMAPI_SUPW_DESC) + 1 +
                1 /* for empty string :-) */ + strlen(user) +
                1 + 16 + 16 + 2 + 2;

    /* We have no setup words, wo we don't account for them */

    pkt_len = SMB_trans_len + 2 /* for bcc */ + strlen(SMB_LMAPI_SLOT) + 1;

    /* Pad things onto a word boundary ... */

    if (pkt_len & 0x0001) {
        pkt_len = pkt_len + 1;
        pad_api_name = TRUE;
    }

    pkt_len = pkt_len + param_len;

    /* Now allocate space for the packet, build it and send it */

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD); /* Should handle the error */

    }

    memset(SMB_Hdr(pkt), 0, SMB_trans_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBtrans;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 14;

    SSVAL(SMB_Hdr(pkt), SMB_trans_tpc_offset, param_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_tdc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_mpc_offset, 4);
    SSVAL(SMB_Hdr(pkt), SMB_trans_mdc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_msc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_flg_offset, 0);
    SIVAL(SMB_Hdr(pkt), SMB_trans_tmo_offset, 5000);
    SSVAL(SMB_Hdr(pkt), SMB_trans_pbc_offset, param_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_pbo_offset, SMB_trans_len + 2 +
          strlen(SMB_LMAPI_SLOT) + 1);
    SSVAL(SMB_Hdr(pkt), SMB_trans_dbc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_dbo_offset, 0);

    /* Now put in the bcc and the rest of the info ... */

    SSVAL(SMB_Hdr(pkt), SMB_trans_len, param_len + strlen(SMB_LMAPI_SLOT) + 1);

    p = SMB_Hdr(pkt) + SMB_trans_len + 2;  /* Skip the BCC and etc */

    strcpy(p, SMB_LMAPI_SLOT);
    p = p + strlen(SMB_LMAPI_SLOT) + 1;

    if (pad_api_name == TRUE)   /* Pad if we need to */
        p = p + 1;

    /*  SSVAL(p, 0, 65000);  /* Check the result */
    SSVAL(p, 0, SMB_LMapi_UserPasswordSet);  /* The api call */

    p = p + 2;

    strcpy(p, SMB_LMAPI_SUPW_DESC);          /* Copy in the param desc */

    p = p + strlen(SMB_LMAPI_SUPW_DESC) + 1;

    *p = 0;                                  /* Stick in that null string */
    p = p + 1;

    strcpy(p, user);

    p = p + strlen(user) + 1;

    strncpy(p, oldpass, 16);

    p = p + 16;

    strncpy(p, newpass, 16);

    p = p + 16;

    SSVAL(p, 0, 0);                 /* Seems to be zero always? */
    SSVAL(p, 2, strlen(newpass));   /* Length of new password ...*/

    /* Now send the lot and get a response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Trans request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Trans request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_trans failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

    /* All ok, pass back the status */

    *apiStatus = SVAL(SMB_Hdr(pkt), SVAL(SMB_Hdr(pkt), SMB_transr_pbo_offset));
    RFCNB_Free_Pkt(pkt);

    return(0);

}

#define SMB_LMAPI_SUI_DESC "zWsTPWW"
#define SMB_LMAPI_SUI_DATA_DESC "B16"

/* Set user info ... specifically, password */

int SMBapi_NetSetUserInfo(SMB_Tree_Handle tree, char *user,
                          char *newpass, int *apiStatus)

{
    struct RFCNB_Pkt *pkt;
    int param_len, i, pkt_len, data_len, pad_api_name = FALSE;
    int pad_params = FALSE;
    char *p;

    /* Get a packet, we need one with space for a transact plus. The calc   */
    /* below lays it all out as it is, including the empty string after the */
    /* descriptor and before the username                                   */

    param_len = 2 + strlen(SMB_LMAPI_SUI_DESC) + 1 +
                + strlen(SMB_LMAPI_SUI_DATA_DESC) + 1 + strlen(user) +
                1 + 2 + 2 + 2 + 2;

    data_len = 16;

    /* We have no setup words, so we don't account for them */

    pkt_len = SMB_trans_len + 2 /* for bcc */ + strlen(SMB_LMAPI_SLOT) + 1;

    if (pkt_len & 0x0001) {   /* Pad to a WORD boundary */

        pad_api_name = TRUE;

    }

    if (param_len & 0x0001) { /* pad to a WORD boundary */

        pad_params = TRUE;

    }

    pkt_len = pkt_len + param_len + data_len;

    if (pad_api_name == TRUE) pkt_len = pkt_len + 1;
    if (pad_params == TRUE) pkt_len = pkt_len + 1;

    /* Now allocate space for the packet, build it and send it */

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD); /* Should handle the error */

    }

    memset(SMB_Hdr(pkt), 0, SMB_trans_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBtrans;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 14;

    SSVAL(SMB_Hdr(pkt), SMB_trans_tpc_offset, param_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_tdc_offset, data_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_mpc_offset, 4);
    SSVAL(SMB_Hdr(pkt), SMB_trans_mdc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_msc_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_trans_flg_offset, 0);
    SIVAL(SMB_Hdr(pkt), SMB_trans_tmo_offset, 5000);
    SSVAL(SMB_Hdr(pkt), SMB_trans_pbc_offset, param_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_pbo_offset, SMB_trans_len + 2 +
          strlen(SMB_LMAPI_SLOT) + 1);
    SSVAL(SMB_Hdr(pkt), SMB_trans_dbc_offset, data_len);
    SSVAL(SMB_Hdr(pkt), SMB_trans_dbo_offset, pkt_len - data_len);

    /* Now put in the bcc and the rest of the info ... */

    SSVAL(SMB_Hdr(pkt), SMB_trans_len, param_len + strlen(SMB_LMAPI_SLOT) +
          1 + data_len);

    p = SMB_Hdr(pkt) + SMB_trans_len + 2;  /* Skip the BCC and etc */

    strcpy(p, SMB_LMAPI_SLOT);
    p = p + strlen(SMB_LMAPI_SLOT) + 1;

    if (pad_api_name == TRUE)     /* Pad to a word boundary */
        p = p + 1;

    /*  SSVAL(p, 0, 65000); */ /* Check the result */
    SSVAL(p, 0, SMB_LMapi_SetUserInfo);  /* The api call */

    p = p + 2;

    strcpy(p, SMB_LMAPI_SUI_DESC);          /* Copy in the param desc */

    p = p + strlen(SMB_LMAPI_SUI_DESC) + 1;

    strcpy(p, SMB_LMAPI_SUI_DATA_DESC);     /* Copy in second descriptor */

    p = p + strlen(SMB_LMAPI_SUI_DATA_DESC) + 1;

    strcpy(p, user);

    p = p + strlen(user) + 1;

    SSVAL(p, 0, 1);                  /* Claim that we have a level 1 struct ? */

    p = p + 2;

    SSVAL(p, 0, 3);                 /* Set the password */
    SSVAL(p, 2, 1);                 /* Seems to be one ... */
    SSVAL(p, 4, strlen(newpass));   /* Length of new password ...*/

    /* Now copy the data in ... */

    p = p + 6;

    if (pad_params == TRUE)
        p = p + 1;

    strcpy(p, newpass);

    /* Now send the lot and get a response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Trans SetUserInfo request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Trans SetUserInfo request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_trans SetUserInfo failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

    /* All ok, pass back the status */

    *apiStatus = SVAL(SMB_Hdr(pkt), SVAL(SMB_Hdr(pkt), SMB_transr_pbo_offset));
    RFCNB_Free_Pkt(pkt);

    return(0);

}

/* List all the shares available on a server */

int SMBapi_NetShareEnum(SMB_Tree_Handle tree, char *enum_buf, int bufsiz,
                        int *shares_returned, int *shares_total)

{

}

