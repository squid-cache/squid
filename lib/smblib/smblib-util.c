#include "squid.h"

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMBlib Utility Routines

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

#include "smblib/smblib.h"
#include "smblib/smblib-priv.h"
#include "rfcnb/rfcnb.h"

#if HAVE_STRING_H
#include <string.h>
#endif

int SMB_Types[] = {SMB_P_Core,
                   SMB_P_CorePlus,
                   SMB_P_DOSLanMan1,
                   SMB_P_DOSLanMan1,
                   SMB_P_LanMan1,
                   SMB_P_DOSLanMan2,
                   SMB_P_LanMan2,
                   SMB_P_LanMan2_1,
                   SMB_P_LanMan2_1,
                   SMB_P_NT1,
                   SMB_P_NT1,
                   SMB_P_NT1,
                   -1
                  };

#if UNDEFINED
char *SMB_DOSTimToStr(int DOS_time);
char *SMB_AtrToStr(int attribs, BOOL verbose);
int SMB_Get_Tree_MBS(SMB_Tree_Handle tree);
int SMB_Get_Max_Buf_Siz(SMB_Handle_Type Con_Handle);
int SMB_Get_Protocol_IDX(SMB_Handle_Type Con_Handle);
#endif /* UNDEFINED */
int SMB_Get_Protocol(SMB_Handle_Type Con_Handle);
int SMB_Figure_Protocol(const char *dialects[], int prot_index);
int SMB_TreeDisconnect(SMB_Tree_Handle Tree_Handle, BOOL discard);

#if UNDEFINED
/* Print out an SMB pkt in all its gory detail ... */

void SMB_Print_Pkt(FILE fd, RFCNB_Pkt *pkt, BOOL command, int Offset, int Len)

{

    /* Well, just how do we do this ... print it I suppose */

    /* Print out the SMB header ...                        */

    /* Print the command                                   */

    /* Print the other bits in the header                  */

    /* etc                                                 */

}
#endif

/* Convert a DOS Date_Time to a local host type date time for printing */

#if UNDEFINED
char *SMB_DOSTimToStr(int DOS_time)

{
    static char SMB_Time_Temp[48];
    int DOS_sec, DOS_min, DOS_hour, DOS_day, DOS_month, DOS_year;

    SMB_Time_Temp[0] = 0;

    DOS_sec   = (DOS_time & 0x001F) * 2;
    DOS_min   = (DOS_time & 0x07E0) >> 5;
    DOS_hour  = ((DOS_time & 0xF800) >> 11);

    DOS_day   = (DOS_time & 0x001F0000) >> 16;
    DOS_month = (DOS_time & 0x01E00000) >> 21;
    DOS_year  = ((DOS_time & 0xFE000000) >> 25) + 80;

    snprintf(SMB_Time_Temp, 48, "%2d/%02d/%2d %2d:%02d:%02d", DOS_day, DOS_month,
             DOS_year, DOS_hour, DOS_min, DOS_sec);

    return(SMB_Time_Temp);

}

/* Convert an attribute byte/word etc to a string ... We return a pointer
   to a static string which we guarantee is long enough. If verbose is
   true, we print out long form of strings ...                            */

char *SMB_AtrToStr(int attribs, BOOL verbose)

{
    static char SMB_Attrib_Temp[128];

    SMB_Attrib_Temp[0] = 0;

    if (attribs & SMB_FA_ROF)
        strcat(SMB_Attrib_Temp, (verbose?"Read Only ":"R"));

    if (attribs & SMB_FA_HID)
        strcat(SMB_Attrib_Temp, (verbose?"Hidden ":"H"));

    if (attribs & SMB_FA_SYS)
        strcat(SMB_Attrib_Temp, (verbose?"System ":"S"));

    if (attribs & SMB_FA_VOL)
        strcat(SMB_Attrib_Temp, (verbose?"Volume ":"V"));

    if (attribs & SMB_FA_DIR)
        strcat(SMB_Attrib_Temp, (verbose?"Directory ":"D"));

    if (attribs & SMB_FA_ARC)
        strcat(SMB_Attrib_Temp, (verbose?"Archive ":"A"));

    return(SMB_Attrib_Temp);

}

/* Pick up the Max Buffer Size from the Tree Structure ... */

int SMB_Get_Tree_MBS(SMB_Tree_Handle tree)

{
    if (tree != NULL) {
        return(tree -> mbs);
    } else {
        return(SMBlibE_BAD);
    }
}

/* Pick up the Max buffer size */

int SMB_Get_Max_Buf_Siz(SMB_Handle_Type Con_Handle)

{
    if (Con_Handle != NULL) {
        return(Con_Handle -> max_xmit);
    } else {
        return(SMBlibE_BAD);
    }

}
/* Pickup the protocol index from the connection structure                 */

int SMB_Get_Protocol_IDX(SMB_Handle_Type Con_Handle)

{
    if (Con_Handle != NULL) {
        return(Con_Handle -> prot_IDX);
    } else {
        return(0xFFFF);  /* Invalid protocol */
    }

}
#endif /* UNDEFINED */

/* Pick up the protocol from the connection structure                       */

int SMB_Get_Protocol(SMB_Handle_Type Con_Handle)

{
    if (Con_Handle != NULL) {
        return(Con_Handle -> protocol);
    } else {
        return(0xFFFF);  /* Invalid protocol */
    }

}

/* Figure out what protocol was accepted, given the list of dialect strings */
/* We offered, and the index back from the server. We allow for a user      */
/* supplied list, and assume that it is a subset of our list                */

int SMB_Figure_Protocol(const char *dialects[], int prot_index)

{
    int i;

    if (dialects == SMB_Prots) { /* The jobs is easy, just index into table */

        return(SMB_Types[prot_index]);
    } else { /* Search through SMB_Prots looking for a match */

        for (i = 0; SMB_Prots[i] != NULL; i++) {

            if (strcmp(dialects[prot_index], SMB_Prots[i]) == 0) { /* A match */

                return(SMB_Types[i]);

            }

        }

        /* If we got here, then we are in trouble, because the protocol was not */
        /* One we understand ...                                                */

        return(SMB_P_Unknown);

    }

}

/* Negotiate the protocol we will use from the list passed in Prots       */
/* we return the index of the accepted protocol in NegProt, -1 indicates  */
/* none acceptible, and our return value is 0 if ok, <0 if problems       */

int SMB_Negotiate(SMB_Handle_Type Con_Handle, const char *Prots[])

{
//    struct SMB_Neg_Prot_Def *prot_pkt;
//    struct SMB_Neg_Prot_Resp_Def *resp_pkt;
    struct RFCNB_Pkt *pkt;
    int prots_len, i, pkt_len, prot, alloc_len;
    char *p;

    /* Figure out how long the prot list will be and allocate space for it */

    prots_len = 0;

    for (i = 0; Prots[i] != NULL; i++) {

        prots_len = prots_len + strlen(Prots[i]) + 2; /* Account for null etc */

    }

    /* The -1 accounts for the one byte smb_buf we have because some systems */
    /* don't like char msg_buf[]                                             */

    pkt_len = SMB_negp_len + prots_len;

    /* Make sure that the pkt len is long enough for the max response ...   */
    /* Which is a problem, because the encryption key len eec may be long   */

    if (pkt_len < (SMB_hdr_wct_offset + (19 * 2) + 40)) {

        alloc_len = SMB_hdr_wct_offset + (19 * 2) + 40;

    } else {

        alloc_len = pkt_len;

    }

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(alloc_len);

    if (pkt == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_negp_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBnegprot;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_negp_bcc_offset, prots_len);

    /* Now copy the prot strings in with the right stuff */

    p = (char *)(SMB_Hdr(pkt) + SMB_negp_buf_offset);

    for (i = 0; Prots[i] != NULL; i++) {

        *p = SMBdialectID;
        strcpy(p + 1, Prots[i]);
        p = p + strlen(Prots[i]) + 2; /* Adjust len of p for null plus dialectID */

    }

    /* Now send the packet and sit back ... */

    if (RFCNB_Send(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending negotiate protocol\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed; /* Failed, check lower layer errno */
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle -> Trans_Connect, pkt, alloc_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to negotiate\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed; /* Failed, check lower layer errno */
        return(SMBlibE_BAD);

    }

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Negotiate failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

    if (SVAL(SMB_Hdr(pkt), SMB_negrCP_idx_offset) == 0xFFFF) {

#ifdef DEBUG
        fprintf(stderr, "None of our protocols was accepted ... ");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_NegNoProt;
        return(SMBlibE_BAD);

    }

    /* Now, unpack the info from the response, if any and evaluate the proto */
    /* selected. We must make sure it is one we like ...                     */

    Con_Handle -> prot_IDX = prot = SVAL(SMB_Hdr(pkt), SMB_negrCP_idx_offset);
    Con_Handle -> protocol = SMB_Figure_Protocol(Prots, prot);

    if (Con_Handle -> protocol == SMB_P_Unknown) { /* No good ... */

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_ProtUnknown;
        return(SMBlibE_BAD);

    }

    switch (CVAL(SMB_Hdr(pkt), SMB_hdr_wct_offset)) {

    case 0x01:      /* No more info ... */

        break;

    case 13:        /* Up to and including LanMan 2.1 */

        Con_Handle -> Security = SVAL(SMB_Hdr(pkt), SMB_negrLM_sec_offset);
        Con_Handle -> encrypt_passwords = ((Con_Handle -> Security & SMB_sec_encrypt_mask) != 0x00);
        Con_Handle -> Security = Con_Handle -> Security & SMB_sec_user_mask;

        Con_Handle -> max_xmit = SVAL(SMB_Hdr(pkt), SMB_negrLM_mbs_offset);
        Con_Handle -> MaxMPX = SVAL(SMB_Hdr(pkt), SMB_negrLM_mmc_offset);
        Con_Handle -> MaxVC = SVAL(SMB_Hdr(pkt), SMB_negrLM_mnv_offset);
        Con_Handle -> Raw_Support = SVAL(SMB_Hdr(pkt), SMB_negrLM_rm_offset);
        Con_Handle -> SessionKey = IVAL(SMB_Hdr(pkt), SMB_negrLM_sk_offset);
        Con_Handle -> SvrTZ = SVAL(SMB_Hdr(pkt), SMB_negrLM_stz_offset);
        Con_Handle -> Encrypt_Key_Len = SVAL(SMB_Hdr(pkt), SMB_negrLM_ekl_offset);

        p = (SMB_Hdr(pkt) + SMB_negrLM_buf_offset);
        memcpy(Con_Handle->Encrypt_Key, p, 8);

        p = (SMB_Hdr(pkt) + SMB_negrLM_buf_offset + Con_Handle -> Encrypt_Key_Len);

        strncpy(p, Con_Handle -> Svr_PDom, sizeof(Con_Handle -> Svr_PDom) - 1);

        break;

    case 17:        /* NT LM 0.12 and LN LM 1.0 */

        Con_Handle -> Security = SVAL(SMB_Hdr(pkt), SMB_negrNTLM_sec_offset);
        Con_Handle -> encrypt_passwords = ((Con_Handle -> Security & SMB_sec_encrypt_mask) != 0x00);
        Con_Handle -> Security = Con_Handle -> Security & SMB_sec_user_mask;

        Con_Handle -> max_xmit = IVAL(SMB_Hdr(pkt), SMB_negrNTLM_mbs_offset);
        Con_Handle -> MaxMPX = SVAL(SMB_Hdr(pkt), SMB_negrNTLM_mmc_offset);
        Con_Handle -> MaxVC = SVAL(SMB_Hdr(pkt), SMB_negrNTLM_mnv_offset);
        Con_Handle -> MaxRaw = IVAL(SMB_Hdr(pkt), SMB_negrNTLM_mrs_offset);
        Con_Handle -> SessionKey = IVAL(SMB_Hdr(pkt), SMB_negrNTLM_sk_offset);
        Con_Handle -> SvrTZ = SVAL(SMB_Hdr(pkt), SMB_negrNTLM_stz_offset);
        Con_Handle -> Encrypt_Key_Len = CVAL(SMB_Hdr(pkt), SMB_negrNTLM_ekl_offset);

        p = (SMB_Hdr(pkt) + SMB_negrNTLM_buf_offset);
        memcpy(Con_Handle->Encrypt_Key, p, 8);

        p = (SMB_Hdr(pkt) + SMB_negrLM_buf_offset + Con_Handle -> Encrypt_Key_Len);

        strncpy(p, Con_Handle -> Svr_PDom, sizeof(Con_Handle -> Svr_PDom) - 1);

        break;

    default:

#ifdef DEBUG
        fprintf(stderr, "Unknown NegProt response format ... Ignored\n");
        fprintf(stderr, "  wct = %i\n", CVAL(SMB_Hdr(pkt), SMB_hdr_wct_offset));
#endif

        break;
    }

#ifdef DEBUG
    fprintf(stderr, "Protocol selected is: %i:%s\n", prot, Prots[prot]);
#endif

    RFCNB_Free_Pkt(pkt);
    return(0);

}

/* Get our hostname */

void SMB_Get_My_Name(char *name, int len)

{
    if (gethostname(name, len) < 0) { /* Error getting name */

        strncpy(name, "unknown", len);

        /* Should check the error */

#ifdef DEBUG
        fprintf(stderr, "gethostname in SMB_Get_My_Name returned error:");
        perror("");
#endif

    } else {
        char *address;
        /* only keep the portion up to the first "." */
        if (NULL != (address = strchr(name, '.'))) {
            *address = '\0';   /* truncate at first '.' */
        }
    }
}

/* Send a TCON to the remote server ...               */

SMB_Tree_Handle SMB_TreeConnect(SMB_Handle_Type Con_Handle,
                                SMB_Tree_Handle Tree_Handle,
                                const char *path,
                                const char *password,
                                const char *device)

{
    struct RFCNB_Pkt *pkt;
    int param_len, pkt_len;
    char *p;
    SMB_Tree_Handle tree;

    /* Figure out how much space is needed for path, password, dev ... */

    if ((path == NULL) | (password == NULL) | (device == NULL)) {

#ifdef DEBUG
        fprintf(stderr, "Bad parameter passed to SMB_TreeConnect\n");
#endif

        SMBlib_errno = SMBlibE_BadParam;
        return(NULL);

    }

    /* The + 2 is because of the \0 and the marker ...                    */

    param_len = strlen(path) + 2 + strlen(password) + 2 + strlen(device) + 2;

    /* The -1 accounts for the one byte smb_buf we have because some systems */
    /* don't like char msg_buf[]                                             */

    pkt_len = SMB_tcon_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(NULL); /* Should handle the error */

    }

    /* Now allocate a tree for this to go into ... */

    if (Tree_Handle == NULL) {

        tree = (SMB_Tree_Handle)malloc(sizeof(struct SMB_Tree_Structure));

        if (tree == NULL) {

            RFCNB_Free_Pkt(pkt);
            SMBlib_errno = SMBlibE_NoSpace;
            return(NULL);

        }
    } else {

        tree = Tree_Handle;

    }

    tree -> next = tree -> prev = NULL;
    tree -> con = Con_Handle;
    strncpy(tree -> path, path, sizeof(tree -> path));
    strncpy(tree -> device_type, device, sizeof(tree -> device_type));

    /* Now plug in the values ... */

    memset(SMB_Hdr(pkt), 0, SMB_tcon_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBtcon;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_tcon_bcc_offset, param_len);

    /* Now copy the param strings in with the right stuff */

    p = (char *)(SMB_Hdr(pkt) + SMB_tcon_buf_offset);
    *p = SMBasciiID;
    strcpy(p + 1, path);
    p = p + strlen(path) + 2;
    *p = SMBasciiID;
    strcpy(p + 1, password);
    p = p + strlen(password) + 2;
    *p = SMBasciiID;
    strcpy(p + 1, device);

    /* Now send the packet and sit back ... */

    if (RFCNB_Send(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending TCon request\n");
#endif

        if (Tree_Handle == NULL)
            free(tree);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(NULL);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Con_Handle -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to TCon\n");
#endif

        if (Tree_Handle == NULL)
            free(tree);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(NULL);

    }

    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_TCon failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        if (Tree_Handle == NULL)
            free(tree);
        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(NULL);

    }

    tree -> tid = SVAL(SMB_Hdr(pkt), SMB_tconr_tid_offset);
    tree -> mbs = SVAL(SMB_Hdr(pkt), SMB_tconr_mbs_offset);

#ifdef DEBUG
    fprintf(stderr, "TConn succeeded, with TID=%i, Max Xmit=%i\n",
            tree -> tid, tree -> mbs);
#endif

    /* Now link the Tree to the Server Structure ... */

    if (Con_Handle -> first_tree == NULL) {

        Con_Handle -> first_tree = tree;
        Con_Handle -> last_tree = tree;

    } else {

        Con_Handle -> last_tree -> next = tree;
        tree -> prev = Con_Handle -> last_tree;
        Con_Handle -> last_tree = tree;

    }

    RFCNB_Free_Pkt(pkt);
    return(tree);

}

int SMB_TreeDisconnect(SMB_Tree_Handle Tree_Handle, BOOL discard)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len;

    pkt_len = SMB_tdis_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD); /* Should handle the error */

    }

    /* Now plug in the values ... */

    memset(SMB_Hdr(pkt), 0, SMB_tdis_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBtdis;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Tree_Handle -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Tree_Handle -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Tree_Handle -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, Tree_Handle -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_tcon_bcc_offset, 0);

    /* Now send the packet and sit back ... */

    if (RFCNB_Send(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending TDis request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to TCon\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_TDis failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);

    }

    Tree_Handle -> tid = 0xFFFF;        /* Invalid TID */
    Tree_Handle -> mbs = 0;             /* Invalid     */

#ifdef DEBUG

    fprintf(stderr, "Tree disconnect successful ...\n");

#endif

    /* What about the tree handle ? */

    if (discard == TRUE) { /* Unlink it and free it ... */

        if (Tree_Handle -> next == NULL)
            Tree_Handle -> con -> first_tree = Tree_Handle -> prev;
        else
            Tree_Handle -> next -> prev = Tree_Handle -> prev;

        if (Tree_Handle -> prev == NULL)
            Tree_Handle -> con -> last_tree = Tree_Handle -> next;
        else
            Tree_Handle -> prev -> next = Tree_Handle -> next;

    }

    RFCNB_Free_Pkt(pkt);
    return(0);

}

/* Pick up the last LMBlib error ... */

int SMB_Get_Last_Error()

{

    return(SMBlib_errno);

}

/* Pick up the last error returned in an SMB packet          */
/* We will need macros to extract error class and error code */

int SMB_Get_Last_SMB_Err()

{

    return(SMBlib_SMB_Error);

}

/* Pick up the error message associated with an error from SMBlib  */

/* Keep this table in sync with the message codes in smblib-common.h */

static const char *SMBlib_Error_Messages[] = {

    "Request completed successfully.",
    "Server returned a non-zero SMB Error Class and Code.",
    "A lower layer protocol error occurred.",
    "Function not yet implemented.",
    "The protocol negotiated does not support the request.",
    "No space available for operation.",
    "One or more bad parameters passed.",
    "None of the protocols we offered were accepted.",
    "The attempt to send an SMB request failed. See protocol error info.",
    "The attempt to get an SMB response failed. See protocol error info.",
    "The logon request failed, but you were logged in as guest.",
    "The attempt to call the remote server failed. See protocol error info.",
    "The protocol dialect specified in a NegProt and accepted by the server is unknown.",
    /* This next one simplifies error handling */
    "No such error code.",
    NULL
};

void SMB_Get_Error_Msg(int msg, char *msgbuf, int len)

{

    if (msg >= 0) {

        strncpy(msgbuf,
                SMBlib_Error_Messages[msg>SMBlibE_NoSuchMsg?SMBlibE_NoSuchMsg:msg],
                len - 1);
        msgbuf[len - 1] = 0; /* Make sure it is a string */
    } else { /* Add the lower layer message ... */

        char prot_msg[1024];

        msg = -msg;   /* Make it positive */

        strncpy(msgbuf,
                SMBlib_Error_Messages[msg>SMBlibE_NoSuchMsg?SMBlibE_NoSuchMsg:msg],
                len - 1);

        msgbuf[len - 1] = 0; /* make sure it is a string */

        if (strlen(msgbuf) < len) { /* If there is space, put rest in */

            strncat(msgbuf, "\n\t", len - strlen(msgbuf));

            RFCNB_Get_Error(prot_msg, sizeof(prot_msg) - 1);

            strncat(msgbuf, prot_msg, len - strlen(msgbuf));

        }
    }

}
