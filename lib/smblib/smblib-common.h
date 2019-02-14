/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMBlib Common Defines

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

#ifndef _SMBLIB_SMBLIB_COMMON_H
#define _SMBLIB_SMBLIB_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/* To get the error class we want the first 8 bits */
/* Because we just grab 4bytes from the SMB header, we have to re-order */
/* here, but it makes the NtStatus part easier in future                */

#define SMBlib_Error_Class(p) (p & 0x000000FF)

/* To get the error code, we want the bottom 16 bits */

#define SMBlib_Error_Code(p) (((unsigned int)p & 0xFFFF0000) >>16)

/* Error CLASS codes and etc ... */

#define SMBC_SUCCESS        0
#define SMBC_ERRDOS         0x01
#define SMBC_ERRSRV         0x02
#define SMBC_ERRHRD         0x03
#define SMBC_ERRCMD         0xFF

/* Success error codes    */

#define SMBS_BUFFERED       0x54
#define SMBS_LOGGED         0x55
#define SMBS_DISPLAYED      0x56

/* ERRDOS Error codes     */

#define SMBD_badfunc        0x01
#define SMBD_badfile        0x02
#define SMBD_badpath        0x03
#define SMBD_nofids         0x04
#define SMBD_noaccess       0x05
#define SMBD_badfid         0x06
#define SMBD_badmcb         0x07
#define SMBD_nomem          0x08
#define SMBD_badmem         0x09
#define SMBD_badenv         0x0A
#define SMBD_badformat      0x0B
#define SMBD_badaccess      0x0C
#define SMBD_baddata        0x0D
#define SMBD_reserved       0x0E
#define SMBD_baddrive       0x0F
#define SMBD_remcd          0x10
#define SMBD_diffdevice     0x11
#define SMBD_nofiles        0x12
#define SMBD_badshare       0x20
#define SMBD_errlock        0x21
#define SMBD_filexists      0x50

/* Server errors ... */

#define SMBV_error          0x01         /* Generic error */
#define SMBV_badpw          0x02
#define SMBV_badtype        0x03
#define SMBV_access         0x04
#define SMBV_invnid         0x05
#define SMBV_invnetname     0x06
#define SMBV_invdevice      0x07
#define SMBV_qfull          0x31
#define SMBV_qtoobig        0x32
#define SMBV_qeof           0x33
#define SMBV_invpfid        0x34
#define SMBV_paused         0x51
#define SMBV_msgoff         0x52
#define SMBV_noroom         0x53
#define SMBV_rmuns          0x57
#define SMBV_nosupport      0xFFFF

/* Hardware error codes ... */

#define SMBH_nowrite        0x13
#define SMBH_badunit        0x14
#define SMBH_notready       0x15
#define SMBH_badcmd         0x16
#define SMBH_data           0x17
#define SMBH_badreq         0x18
#define SMBH_seek           0x19
#define SMBH_badmedia       0x1A
#define SMBH_badsector      0x1B
#define SMBH_nopaper        0x1C
#define SMBH_write          0x1D
#define SMBH_read           0x1E
#define SMBH_general        0x1F
#define SMBH_badshare       0x20

/* Access mode defines ... */

#define SMB_AMODE_WTRU      0x4000
#define SMB_AMODE_NOCACHE   0x1000
#define SMB_AMODE_COMPAT    0x0000
#define SMB_AMODE_DENYRWX   0x0010
#define SMB_AMODE_DENYW     0x0020
#define SMB_AMODE_DENYRX    0x0030
#define SMB_AMODE_DENYNONE  0x0040
#define SMB_AMODE_OPENR     0x0000
#define SMB_AMODE_OPENW     0x0001
#define SMB_AMODE_OPENRW    0x0002
#define SMB_AMODE_OPENX     0x0003
#define SMB_AMODE_FCBOPEN   0x00FF
#define SMB_AMODE_LOCUNKN   0x0000
#define SMB_AMODE_LOCMSEQ   0x0100
#define SMB_AMODE_LOCMRAN   0x0200
#define SMB_AMODE_LOCRAL    0x0300

/* File attribute encoding ... */

#define SMB_FA_ORD          0x00
#define SMB_FA_ROF          0x01
#define SMB_FA_HID          0x02
#define SMB_FA_SYS          0x04
#define SMB_FA_VOL          0x08
#define SMB_FA_DIR          0x10
#define SMB_FA_ARC          0x20

/* Define the protocol types ... */

#define SMB_P_Unknown      -1        /* Hmmm, is this smart? */
#define SMB_P_Core         0
#define SMB_P_CorePlus     1
#define SMB_P_DOSLanMan1   2
#define SMB_P_LanMan1      3
#define SMB_P_DOSLanMan2   4
#define SMB_P_LanMan2      5
#define SMB_P_DOSLanMan2_1 6
#define SMB_P_LanMan2_1    7
#define SMB_P_NT1          8

/* SMBlib return codes */
/* We want something that indicates whether or not the return code was a   */
/* remote error, a local error in SMBlib or returned from lower layer ...  */
/* Wonder if this will work ...                                            */
/* SMBlibE_Remote = 1 indicates remote error                               */
/* SMBlibE_ values < 0 indicate local error with more info available       */
/* SMBlibE_ values >1 indicate local from SMBlib code errors?              */

#define SMBlibE_Success 0
#define SMBlibE_Remote  1    /* Remote error, get more info from con        */
#define SMBlibE_BAD     -1
#define SMBlibE_LowerLayer 2 /* Lower layer error                           */
#define SMBlibE_NotImpl 3    /* Function not yet implemented                */
#define SMBlibE_ProtLow 4    /* Protocol negotiated does not support req    */
#define SMBlibE_NoSpace 5    /* No space to allocate a structure            */
#define SMBlibE_BadParam 6   /* Bad parameters                              */
#define SMBlibE_NegNoProt 7  /* None of our protocols was liked             */
#define SMBlibE_SendFailed 8 /* Sending an SMB failed                       */
#define SMBlibE_RecvFailed 9 /* Receiving an SMB failed                     */
#define SMBlibE_GuestOnly 10 /* Logged in as guest                          */
#define SMBlibE_CallFailed 11 /* Call remote end failed                     */
#define SMBlibE_ProtUnknown 12 /* Protocol unknown                          */
#define SMBlibE_NoSuchMsg  13 /* Keep this up to date                       */

/* the default SMB protocols supported by this library. */
extern const char *SMB_Prots[];

typedef struct {                       /* A structure for a Dirent */

    unsigned char resume_key[21];        /* Don't touch this          */
    unsigned char file_attributes;       /* Attributes of file        */
    unsigned int date_time;              /* date and time of last mod */
    unsigned int size;
    char filename[13];                   /* The name of the file      */

} SMB_CP_dirent;

typedef struct SMB_Connect_Def * SMB_Handle_Type;

typedef struct SMB_Tree_Structure * SMB_Tree_Handle;

/* A Tree_Structure                       */

struct SMB_Tree_Structure {

    SMB_Tree_Handle next, prev;
    SMB_Handle_Type con;
    char path[129];
    char device_type[20];
    int mbs;                   /* Local MBS */
    int tid;

};

struct SMB_Connect_Def {
    SMB_Handle_Type Next_Con, Prev_Con;          /* Next and previous conn */
    int protocol;                                /* What is the protocol   */
    int prot_IDX;                                /* And what is the index  */
    void *Trans_Connect;                         /* The connection         */

    /* All these strings should be malloc'd */

    char service[80], username[80], password[80], desthost[80], sock_options[80];
    char address[80], myname[80];

    SMB_Tree_Handle first_tree, last_tree;  /* List of trees on this server */

    int gid;         /* Group ID, do we need it?                      */
    int mid;         /* Multiplex ID? We might need one per con       */
    int pid;         /* Process ID                                    */

    int uid;         /* Authenticated user id.                        */

    /* It is pretty clear that we need to bust some of */
    /* these out into a per TCon record, as there may  */
    /* be multiple TCon's per server, etc ... later    */

    int port;        /* port to use in case not default, this is a TCPism! */

    int max_xmit;    /* Max xmit permitted by server                  */
    int Security;    /* 0 = share, 1 = user                           */
    int Raw_Support; /* bit 0 = 1 = Read Raw supported, 1 = 1 Write raw */
    int encrypt_passwords; /* 1 = do , 0 = don't                      */
    int MaxMPX, MaxVC, MaxRaw;
    unsigned int SessionKey, Capabilities;
    int SvrTZ;                                 /* Server Time Zone */
    int Encrypt_Key_Len;
    char Encrypt_Key[80], Domain[80], PDomain[80], OSName[80], LMType[40];
    char Svr_OS[80], Svr_LMType[80], Svr_PDom[80];
};

#ifdef __cplusplus
}
#endif
#endif /* _SMBLIB_SMBLIB_COMMON_H */

