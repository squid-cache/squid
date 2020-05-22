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

/* Logon and tree connect to the server. If a tree handle was given to us, */
/* we use it and return it, otherwise we create one ...                    */

SMB_Tree_Handle SMB_Logon_And_TCon(SMB_Handle_Type Con_Handle,
                                   SMB_Tree_Handle Tree_Handle,
                                   char *UserName,
                                   char *PassWord,
                                   char *service,
                                   char *service_type)

{
    struct RFCNB_Pkt *pkt;
    int param_len, i, pkt_len, andx_len, andx_param_len;
    char *p, *AndXCom;
    SMB_Tree_Handle tree;

    /* Lets create a tree if we need one ... */

    if (Tree_Handle == NULL) {

        tree = (SMB_Tree_Handle)malloc(sizeof(struct SMB_Tree_Structure));

        if (tree == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            return(tree);

        } else { /* Initialize the tree */

            tree -> con = Con_Handle;
            tree -> prev = tree -> next = NULL;

        }
    } else
        tree = Tree_Handle;

    /* First we need a packet etc ... but we need to know what protocol has  */
    /* been negotiated to figure out if we can do it and what SMB format to  */
    /* use ...                                                               */

    /* Since we are going to do a LogonAndX with a TCon as the second command*/
    /* We need the packet size correct. So TCon starts at wct field          */

    if (Con_Handle -> protocol < SMB_P_LanMan1) {

        SMBlib_errno = SMBlibE_ProtLow;
        if (Tree_Handle == NULL)
            free(tree);
        return(NULL);

    }

    /* Now build the correct structure */

    andx_len = SMB_tconx_len - SMB_hdr_wct_offset;

    /* We send a null password as we sent one in the setup and X */

    andx_param_len = strlen(service) + 1 + strlen(service_type) + 1;

    if (Con_Handle -> protocol < SMB_P_NT1) {

#ifdef SMBLIB_DEBUG
        fprintf(stderr, "Doing an LM session setup etc ...\n");
#endif

        /* We don't do encrypted passwords ... */

        param_len = strlen(UserName) + 1 + strlen(PassWord) + 1 +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1;

        pkt_len = SMB_ssetpLM_len + param_len + andx_len + andx_param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            if (Tree_Handle == NULL)
                free(tree);
            return(NULL); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, 0);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 10;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) =  SMBtconX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, SMB_ssetpLM_len + param_len);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mmc_offset, 2);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_vcn_offset, Con_Handle -> pid);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_pwl_offset, strlen(PassWord) + 1);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_res_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */

        p = (char *)(SMB_Hdr(pkt) + SMB_ssetpLM_buf_offset);

        /* Copy  in password, then the rest. Password has no null at end */

        strcpy(p, PassWord);

        p = p + strlen(PassWord) + 1;

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

        AndXCom = SMB_Hdr(pkt) + SMB_ssetpLM_len + param_len - SMB_hdr_wct_offset;

    } else {

        /* We don't admit to UNICODE support ... */

#ifdef SMBLIB_DEBUG
        fprintf(stderr, "Doing NT LM Sess Setup etc ... \n");
#endif

        param_len = strlen(UserName) + 1 + strlen(PassWord) +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1 +
                    strlen(Con_Handle -> LMType) + 1;

        pkt_len = SMB_ssetpNTLM_len + param_len + andx_len + andx_param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            if (Tree_Handle == NULL)
                free(tree);
            return(NULL); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpNTLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, 0);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 13;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = SMBtconX;
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
        p = p + 1;

        strcpy(p, Con_Handle -> LMType);
        p = p + strlen(Con_Handle -> LMType);
        *p = 0;

        /* Now set up the TCON Part ... from WCT, make up a pointer that will
           help us ...                                                        */

        AndXCom = SMB_Hdr(pkt) + SMB_ssetpNTLM_len + param_len - SMB_hdr_wct_offset;

    }
    *(AndXCom + SMB_hdr_wct_offset) = 4;
    *(AndXCom + SMB_tconx_axc_offset) = 0xFF;  /* No command */
    SSVAL(AndXCom, SMB_tconx_axo_offset, 0);
    SSVAL(AndXCom, SMB_tconx_flg_offset, 0);   /* Don't disconnect TID    */
    SSVAL(AndXCom, SMB_tconx_pwl_offset, 0);   /* No password, */
    SSVAL(AndXCom, SMB_tconx_bcc_offset, andx_param_len);

    p = (char *)(AndXCom + SMB_tconx_buf_offset);

    /**p = 0;
    p = p + 1; */
    strcpy(p, service);
    p = p + strlen(service) + 1;
    strcpy(p, service_type);

    /* Now send it and get a response */

    if (RFCNB_Send(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending SessSetupAndTCon request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        free(tree);
        SMBlib_errno = SMBlibE_SendFailed;
        return(NULL);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to SessSetupAndTCon\n");
#endif

        RFCNB_Free_Pkt(pkt);
        free(tree);
        SMBlib_errno = SMBlibE_RecvFailed;
        return(NULL);

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
        free(tree);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(NULL);

    }

#ifdef DEBUG
    fprintf(stderr, "SessSetupAndX response. Action = %i\n",
            SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset));
#endif

    /* Now pick up the UID for future reference ... */

    Con_Handle -> uid = SVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset);

    /* And pick up the TID as well                  */

    tree -> tid = SVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset);

    tree -> mbs = Con_Handle -> max_xmit;

    /* Link the tree into the list in con */

    if (Con_Handle -> first_tree == NULL) {

        Con_Handle -> first_tree == tree;
        Con_Handle -> last_tree == tree;

    } else {

        Con_Handle -> last_tree -> next = tree;
        tree -> prev = Con_Handle -> last_tree;
        Con_Handle -> last_tree = tree;

    }

    RFCNB_Free_Pkt(pkt);

    return(tree);

}

/* Logon and TCon and Open to a file on the server, but we need to pass   */
/* back a file pointer, so we better have one in the parameter list       */

int SMB_Logon_TCon_Open(SMB_Handle_Type Con_Handle, char *UserName,
                        char *PassWord,
                        char *service,
                        char *service_type,
                        SMB_Tree_Handle *Tree_Handle,
                        char *filename,
                        WORD mode,
                        WORD search,
                        SMB_File **File_Handle)

{
    struct RFCNB_Pkt *pkt;
    int param_len, i, pkt_len, tcon_len, tcon_param_len, open_len,
        open_param_len, header_len;
    struct SMB_File_Def *file_tmp;
    SMB_Tree_Handle tree;
    char *p, *AndXCom;

    /* First, we need a tree STRUCTURE as we are going to tree connect     */

    tree = (SMB_Tree_Handle)malloc(sizeof(struct SMB_Tree_Structure));

    if (tree == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    } else {

        tree -> con = Con_Handle;
        tree -> next = tree -> prev = NULL;

    }

    /* Next, we need a file handle as we are going to pass one back ...    */
    /* Hmm, there is a bug here ... We should check on File_Handle ...     */

    if ((file_tmp = (SMB_File *)malloc(sizeof(SMB_File))) == NULL) {

#ifdef DEBUG
        fprintf(stderr, "Could not allocate file handle space ...");
#endif

        SMBlib_errno = SMBlibE_NoSpace;
        free(tree);
        return(SMBlibE_BAD);

    }

    /* Next we need a packet etc ... but we need to know what protocol has  */
    /* been negotiated to figure out if we can do it and what SMB format to  */
    /* use ...                                                               */

    /* Since we are going to do a LogonAndX with a TCon as the second command*/
    /* We need the packet size correct. So TCon starts at wct field          */

    if (Con_Handle -> protocol < SMB_P_LanMan1) {

        free(tree);
        free(file_tmp);
        SMBlib_errno = SMBlibE_ProtLow;
        return(SMBlibE_BAD);

    }

    /* Now build the correct structure */

    /* We send a null password in the TconAndX ... */

    tcon_len = SMB_tconx_len - SMB_hdr_wct_offset;
    tcon_param_len = strlen(service) + 1 + strlen(service_type) + 1;

    open_len = SMB_openx_len - SMB_hdr_wct_offset;
    open_param_len = 1 + strlen(filename) + 1;  /* AsciiID + null */

    if (Con_Handle -> protocol < SMB_P_NT1) {

        /* We don't do encrypted passwords yet */

        param_len = strlen(UserName) + 1 + strlen(PassWord) + 1 +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1;

        header_len = SMB_ssetpLM_len + param_len;

        pkt_len = header_len + tcon_len + tcon_param_len +
                  open_len + open_param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            free(tree);
            free(file_tmp);
            return(SMBlibE_BAD); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, 0);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 10;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = SMBtconX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, SMB_ssetpLM_len + param_len);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mmc_offset, 2);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_vcn_offset, Con_Handle -> pid);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_pwl_offset, strlen(PassWord) + 1);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_res_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */

        p = (char *)(SMB_Hdr(pkt) + SMB_ssetpLM_buf_offset);

        /* Copy  in password, then the rest. Password has no null at end */

        strcpy(p, PassWord);

        p = p + strlen(PassWord) + 1;

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

        AndXCom = SMB_Hdr(pkt) + SMB_ssetpLM_len + param_len - SMB_hdr_wct_offset;

    } else {

        /* We don't admit to UNICODE support ... */

        param_len = strlen(UserName) + 1 + strlen(PassWord) +
                    strlen(Con_Handle -> PDomain) + 1 +
                    strlen(Con_Handle -> OSName) + 1 +
                    strlen(Con_Handle -> LMType) + 1;

        header_len = SMB_ssetpNTLM_len + param_len;

        pkt_len = header_len + tcon_len + tcon_param_len +
                  open_len + open_param_len;

        pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {

            SMBlib_errno = SMBlibE_NoSpace;
            free(tree);
            free(file_tmp);     /* Should only do if we created one ... */
            return(-1); /* Should handle the error */

        }

        memset(SMB_Hdr(pkt), 0, SMB_ssetpNTLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, 0);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 13;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = SMBtconX;
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
        p = p + 1;

        strcpy(p, Con_Handle -> LMType);
        p = p + strlen(Con_Handle -> LMType);
        *p = 0;

        /* Now set up the TCON Part ... from WCT, make up a pointer that will
           help us ...                                                        */

        AndXCom = SMB_Hdr(pkt) + SMB_ssetpNTLM_len + param_len - SMB_hdr_wct_offset;

    }

    *(AndXCom + SMB_hdr_wct_offset) = 4;
    *(AndXCom + SMB_tconx_axc_offset) = SMBopenX;
    SSVAL(AndXCom, SMB_tconx_axo_offset, (header_len +
                                          tcon_len + tcon_param_len));
    SSVAL(AndXCom, SMB_tconx_flg_offset, 0);   /* Don't disconnect TID    */
    SSVAL(AndXCom, SMB_tconx_pwl_offset, 0);   /* No password */
    SSVAL(AndXCom, SMB_tconx_bcc_offset, tcon_param_len);

    p = (char *)(AndXCom + SMB_tconx_buf_offset);

    /*  *p = 0;
      p = p + 1; */
    strcpy(p, service);
    p = p + strlen(service) + 1;
    strcpy(p, service_type);

    /* Now the open bit ... */

    AndXCom = AndXCom + tcon_len + tcon_param_len;  /* Should get us there */

    *(AndXCom + SMB_hdr_wct_offset) = 15;
    *(AndXCom + SMB_openx_axc_offset) = 0xFF;
    *(AndXCom + SMB_openx_axr_offset) = 0;
    SSVAL(AndXCom, SMB_openx_axo_offset, 0);
    SSVAL(AndXCom, SMB_openx_flg_offset, 0);
    SSVAL(AndXCom, SMB_openx_mod_offset, mode);
    SSVAL(AndXCom, SMB_openx_atr_offset, search);
    SSVAL(AndXCom, SMB_openx_fat_offset, 0);
    SIVAL(AndXCom, SMB_openx_tim_offset, 0);
    SSVAL(AndXCom, SMB_openx_ofn_offset, 0x0011); /* Create or open */
    SIVAL(AndXCom, SMB_openx_als_offset, 0);
    SSVAL(AndXCom, SMB_openx_bcc_offset, open_param_len);

    p = (char *)(AndXCom + SMB_openx_buf_offset);

    /* *p = SMBasciiID; */
    strcpy(p, filename);

    /* Now send it and get a response */

    if (RFCNB_Send(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending SessSetupAndTCon request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        free(tree);
        free(file_tmp);
        SMBlib_errno = SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to SessSetupAndTCon\n");
#endif

        RFCNB_Free_Pkt(pkt);
        free(tree);
        free(file_tmp);
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
        free(tree);
        free(file_tmp);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

#ifdef DEBUG
    fprintf(stderr, "SessSetupAndX response. Action = %i\n",
            SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset));
#endif

    /* Now pick up the UID for future reference ... */

    Con_Handle -> uid = SVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset);

    /* And pick up the TID as well                  */

    tree -> tid = SVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset);
    tree -> mbs = Con_Handle -> max_xmit;        /* We need this */

#ifdef DEBUG
    fprintf(stderr, "mbs=%i\n", tree -> mbs);
#endif

    /* Now we populate the file hanble and pass it back ... */

    strncpy(file_tmp -> filename, filename, sizeof(file_tmp -> filename) - 1);
    file_tmp -> tree = tree;

    /* Pick up a pointer to the right part ... */

    AndXCom = SMB_Hdr(pkt) + SVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset) -
              SMB_hdr_wct_offset;

    /* Now skip the response to the TConX      */

    AndXCom = SMB_Hdr(pkt) + SVAL(AndXCom, SMB_tconxr_axo_offset) -
              SMB_hdr_wct_offset;

#ifdef DEBUG
    fprintf(stderr, "Word Params = %x, AXO = %x\n",
            CVAL(AndXCom, SMB_hdr_wct_offset),
            SVAL(AndXCom, SMB_openxr_axo_offset));
#endif

    /* Now pick up the things from the openX response that we need */

    file_tmp -> fid     = SVAL(AndXCom, SMB_openxr_fid_offset);
    file_tmp -> lastmod = IVAL(AndXCom, SMB_openxr_tim_offset);
    file_tmp -> size    = IVAL(AndXCom, SMB_openxr_fsz_offset);
    file_tmp -> access  = SVAL(AndXCom, SMB_openxr_acc_offset);
    file_tmp -> fileloc = 0;

    *File_Handle = file_tmp;

    /* Now link the tree into the right place ... */

    if (Con_Handle -> first_tree == NULL) {

        Con_Handle -> first_tree == tree;
        Con_Handle -> last_tree == tree;

    } else {

        Con_Handle -> last_tree -> next = tree;
        tree -> prev = Con_Handle -> last_tree;
        Con_Handle -> last_tree = tree;

    }

    RFCNB_Free_Pkt(pkt);

    *Tree_Handle = tree;

    return(0);

}

