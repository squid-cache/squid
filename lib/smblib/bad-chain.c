/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMBlib Routines. Experimental Section ...

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

#include <signal.h>
#if HAVE_STRING_H
#include <string.h>
#endif

/* Logon and tree connect to the server                                 */

int SMB_Logon_And_TCon(SMB_Handle_Type Con_Handle, char *UserName,
                       char *PassWord,
                       char *service,
                       char *service_type)

{
    struct RFCNB_Pkt *pkt;
    int param_len, i, pkt_len, andx_len, andx_param_len;
    char *p, *AndXCom;

    /* First we need a packet etc ... but we need to know what protocol has  */
    /* been negotiated to figure out if we can do it and what SMB format to  */
    /* use ...                                                               */

    /* Since we are going to do a LogonAndX with a TCon as the second command*/
    /* We need the packet size correct. So TCon starts at wct field          */

    if (SMB_Types[Con_Handle -> protocol] < SMB_P_LanMan1) {

        SMBlib_errno = SMBlibE_ProtLow;
        return(SMBlibE_BAD);

    }

    /* Now build the correct structure */

    if (SMB_Types[Con_Handle -> protocol] < SMB_P_NT1) {

        param_len = strlen(UserName) + 1 + strlen(PassWord) +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1;

        pkt_len = SMB_ssetpLM_len + param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            return(SMBlibE_BAD); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle -> uid);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 10;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = 0xFF;    /* No extra command */
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, 0);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mmc_offset, 2);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_vcn_offset, Con_Handle -> pid);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_pwl_offset, strlen(PassWord));
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_res_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */

        p = (char *)(SMB_Hdr(pkt) + SMB_ssetpLM_buf_offset);

        /* Copy  in password, then the rest. Password has no null at end */

        strcpy(p, PassWord);

        p = p + strlen(PassWord);

        strcpy(p, UserName);
        p = p + strlen(UserName);
        *p = 0;

        p = p + 1;

        strcpy(p, Con_Handle -> PDomain);
        p = p + strlen(Con_Handle -> PDomain);
        *p = 0;
        p = p + 1;

        strcpy(p, Con_Handle -> OSName);
        p = p + strlen(Con_Handle -> OSName);
        *p = 0;

    } else {

        /* We don't admit to UNICODE support ... */

        param_len = strlen(UserName) + 1 + strlen(PassWord) +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1;

        andx_len = SMB_tcon_len - SMB_hdr_wct_offset;

        /* We send a null password as we sent one in the setup and X */

        andx_param_len = strlen(service) + 2 + 2 + strlen(service_type) + 2;

        pkt_len = SMB_ssetpNTLM_len + param_len + andx_len + andx_param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            return(-1); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpNTLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle -> uid);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 13;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = SMBtcon;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, SMB_ssetpNTLM_len + param_len);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mmc_offset, 2);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_vcn_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cipl_offset, strlen(PassWord));
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cspl_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_res_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cap_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */

        p = (char *)(SMB_Hdr(pkt) + SMB_ssetpNTLM_buf_offset);

        /* Copy  in password, then the rest. Password has no null at end */

        strcpy(p, PassWord);

        p = p + strlen(PassWord);

        strcpy(p, UserName);
        p = p + strlen(UserName);
        *p = 0;

        p = p + 1;

        strcpy(p, Con_Handle -> PDomain);
        p = p + strlen(Con_Handle -> PDomain);
        *p = 0;
        p = p + 1;

        strcpy(p, Con_Handle -> OSName);
        p = p + strlen(Con_Handle -> OSName);
        *p = 0;

        /* Now set up the TCON Part ... from WCT, make up a pointer that will
           help us ...                                                        */

        AndXCom = SMB_Hdr(pkt) + SMB_ssetpNTLM_len + param_len - SMB_hdr_wct_offset;

        *(AndXCom + SMB_hdr_wct_offset) = 0;   /* No Words */

        SSVAL(AndXCom, SMB_tcon_bcc_offset, andx_param_len);

        p = (char *)(AndXCom + SMB_tcon_buf_offset);

        *p = SMBasciiID;
        strcpy(p + 1, service);
        p = p + strlen(service) + 2;
        *p = SMBasciiID;                    /* No password ... */
        *(p + 1) = 0;
        p = p + 2;
        *p = SMBasciiID;
        strcpy(p + 1, service_type);

    }

    /* Now send it and get a response */

    if (RFCNB_Send(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending SessSetupAndTCon request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to SessSetupAndTCon\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_SessSetupAndTCon failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        /* Note, here, that we have not properly handled the error processing */
        /* and so we cannot tell how much of our request crapped out          */

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

#ifdef DEBUG
    fprintf(stderr, "SessSetupAndX response. Action = %i\n",
            SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset));
#endif

    /* Now pick up the UID for future reference ... */

    Con_Handle -> uid = SVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset);

    /* And pick up the TID as well, which will be at offset 4? from wct */

    AndXCom = (char *)SMB_Hdr(pkt) + SVAL(SMB_Hdr(pkt), SMB_ssetpr_axo_offset);

    Con_Handle -> tid = SVAL(AndXCom, 3);        /* Naughty   */
    Con_Handle -> max_xmit = SVAL(AndXCom, 1);   /* And Again */

    RFCNB_Free_Pkt(pkt);

    return(0);

}

