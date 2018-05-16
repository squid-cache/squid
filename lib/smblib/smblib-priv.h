/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMBlib private Defines

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

#ifndef _SMBLIB_PRIV_H_
#define _SMBLIB_PRIV_H_

#include "smblib/smblib-common.h"
#include "smblib/std-defines.h"
#include <sys/types.h>
#include <unistd.h>

typedef unsigned short uint16;
typedef unsigned int   uint32;

#include "rfcnb/byteorder.h"     /* Hmmm ... hot good */

#ifndef max
#define max(a,b) (a < b ? b : a)
#endif

#define SMB_DEF_IDF 0x424D53FF        /* "\377SMB" */

/* Core protocol commands */

#define SMBmkdir      0x00   /* create directory */
#define SMBrmdir      0x01   /* delete directory */
#define SMBopen       0x02   /* open file */
#define SMBcreate     0x03   /* create file */
#define SMBclose      0x04   /* close file */
#define SMBflush      0x05   /* flush file */
#define SMBunlink     0x06   /* delete file */
#define SMBmv         0x07   /* rename file */
#define SMBgetatr     0x08   /* get file attributes */
#define SMBsetatr     0x09   /* set file attributes */
#define SMBread       0x0A   /* read from file */
#define SMBwrite      0x0B   /* write to file */
#define SMBlock       0x0C   /* lock byte range */
#define SMBunlock     0x0D   /* unlock byte range */
#define SMBctemp      0x0E   /* create temporary file */
#define SMBmknew      0x0F   /* make new file */
#define SMBchkpth     0x10   /* check directory path */
#define SMBexit       0x11   /* process exit */
#define SMBlseek      0x12   /* seek */
#define SMBtcon       0x70   /* tree connect */
#define SMBtdis       0x71   /* tree disconnect */
#define SMBnegprot    0x72   /* negotiate protocol */
#define SMBdskattr    0x80   /* get disk attributes */
#define SMBsearch     0x81   /* search directory */
#define SMBsplopen    0xC0   /* open print spool file */
#define SMBsplwr      0xC1   /* write to print spool file */
#define SMBsplclose   0xC2   /* close print spool file */
#define SMBsplretq    0xC3   /* return print queue */
#define SMBsends      0xD0   /* send single block message */
#define SMBsendb      0xD1   /* send broadcast message */
#define SMBfwdname    0xD2   /* forward user name */
#define SMBcancelf    0xD3   /* cancel forward */
#define SMBgetmac     0xD4   /* get machine name */
#define SMBsendstrt   0xD5   /* send start of multi-block message */
#define SMBsendend    0xD6   /* send end of multi-block message */
#define SMBsendtxt    0xD7   /* send text of multi-block message */

/* CorePlus protocol                                        */

#define SMBlockread   0x13  /* Lock a range and read it */
#define SMBwriteunlock 0x14 /* Unlock a range and then write */
#define SMBreadbraw   0x1a  /* read a block of data without smb header ohead*/
#define SMBwritebraw  0x1d  /* write a block of data without smb header ohead*/
#define SMBwritec     0x20  /* secondary write request */
#define SMBwriteclose 0x2c  /* write a file and then close it */

/* DOS Extended Protocol                                    */

#define SMBreadBraw      0x1A   /* read block raw */
#define SMBreadBmpx      0x1B   /* read block multiplexed */
#define SMBreadBs        0x1C   /* read block (secondary response) */
#define SMBwriteBraw     0x1D   /* write block raw */
#define SMBwriteBmpx     0x1E   /* write block multiplexed */
#define SMBwriteBs       0x1F   /* write block (secondary request) */
#define SMBwriteC        0x20   /* write complete response */
#define SMBsetattrE      0x22   /* set file attributes expanded */
#define SMBgetattrE      0x23   /* get file attributes expanded */
#define SMBlockingX      0x24   /* lock/unlock byte ranges and X */
#define SMBtrans         0x25   /* transaction - name, bytes in/out */
#define SMBtranss        0x26   /* transaction (secondary request/response) */
#define SMBioctl         0x27   /* IOCTL */
#define SMBioctls        0x28   /* IOCTL  (secondary request/response) */
#define SMBcopy          0x29   /* copy */
#define SMBmove          0x2A   /* move */
#define SMBecho          0x2B   /* echo */
#define SMBopenX         0x2D   /* open and X */
#define SMBreadX         0x2E   /* read and X */
#define SMBwriteX        0x2F   /* write and X */
#define SMBsesssetupX    0x73   /* Session Set Up & X (including User Logon) */
#define SMBtconX         0x75   /* tree connect and X */
#define SMBffirst        0x82   /* find first */
#define SMBfunique       0x83   /* find unique */
#define SMBfclose        0x84   /* find close */
#define SMBinvalid       0xFE   /* invalid command */

/* Any more ? */

#define SMBdatablockID     0x01  /* A data block identifier */
#define SMBdialectID       0x02  /* A dialect id            */
#define SMBpathnameID      0x03  /* A pathname ID           */
#define SMBasciiID         0x04  /* An ascii string ID      */
#define SMBvariableblockID 0x05  /* A variable block ID     */

/* some other defines we need */

/* Flags defines ... */

#define SMB_FLG2_NON_DOS    0x01 /* We know non dos names             */
#define SMB_FLG2_EXT_ATR    0x02 /* We know about Extended Attributes */
#define SMB_FLG2_LNG_NAM    0x04 /* Long names ?                      */

typedef unsigned short WORD;
typedef unsigned short UWORD;
typedef unsigned int ULONG;
typedef unsigned char BYTE;
typedef unsigned char UCHAR;

/* Some macros to allow access to actual packet data so that we */
/* can change the underlying representation of packets.         */
/*                                                              */
/* The current formats vying for attention are a fragment       */
/* approach where the SMB header is a fragment linked to the    */
/* data portion with the transport protocol (rfcnb or whatever) */
/* being linked on the front.                                   */
/*                                                              */
/* The other approach is where the whole packet is one array    */
/* of bytes with space allowed on the front for the packet      */
/* headers.                                                     */

#define SMB_Hdr(p) (char *)(p -> data)

/* SMB Hdr def for File Sharing Protocol? From MS and Intel,    */
/* Intel PN 138446 Doc Version 2.0, Nov 7, 1988. This def also  */
/* applies to LANMAN1.0 as well as the Core Protocol            */
/* The spec states that wct and bcc must be present, even if 0  */

/* We define these as offsets into a char SMB[] array for the   */
/* sake of portability                                          */

/* NOTE!. Some of the length defines, SMB_<protreq>_len do not include */
/* the data that follows in the SMB packet, so the code will have to   */
/* take that into account.                                             */

#define SMB_hdr_idf_offset    0          /* 0xFF,'SMB' 0-3 */
#define SMB_hdr_com_offset    4          /* BYTE       4   */
#define SMB_hdr_rcls_offset   5          /* BYTE       5   */
#define SMB_hdr_reh_offset    6          /* BYTE       6   */
#define SMB_hdr_err_offset    7          /* WORD       7   */
#define SMB_hdr_reb_offset    9          /* BYTE       9   */
#define SMB_hdr_flg_offset    9          /* same as reb ...*/
#define SMB_hdr_res_offset    10         /* 7 WORDs    10  */
#define SMB_hdr_res0_offset   10         /* WORD       10  */
#define SMB_hdr_flg2_offset   10         /* WORD           */
#define SMB_hdr_res1_offset   12         /* WORD       12  */
#define SMB_hdr_res2_offset   14
#define SMB_hdr_res3_offset   16
#define SMB_hdr_res4_offset   18
#define SMB_hdr_res5_offset   20
#define SMB_hdr_res6_offset   22
#define SMB_hdr_tid_offset    24
#define SMB_hdr_pid_offset    26
#define SMB_hdr_uid_offset    28
#define SMB_hdr_mid_offset    30
#define SMB_hdr_wct_offset    32

#define SMB_hdr_len           33        /* 33 byte header?      */

#define SMB_hdr_axc_offset    33        /* AndX Command         */
#define SMB_hdr_axr_offset    34        /* AndX Reserved        */
#define SMB_hdr_axo_offset    35     /* Offset from start to WCT of AndX cmd */

/* Format of the Negotiate Protocol SMB */

#define SMB_negp_bcc_offset   33
#define SMB_negp_buf_offset   35        /* Where the buffer starts   */
#define SMB_negp_len          35        /* plus the data             */

/* Format of the Negotiate Response SMB, for CoreProtocol, LM1.2 and */
/* NT LM 0.12. wct will be 1 for CoreProtocol, 13 for LM 1.2, and 17 */
/* for NT LM 0.12                                                    */

#define SMB_negrCP_idx_offset   33        /* Response to the neg req */
#define SMB_negrCP_bcc_offset   35
#define SMB_negrLM_idx_offset   33        /* dialect index           */
#define SMB_negrLM_sec_offset   35        /* Security mode           */
#define SMB_sec_user_mask       0x01      /* 0 = share, 1 = user     */
#define SMB_sec_encrypt_mask    0x02      /* pick out encrypt        */
#define SMB_negrLM_mbs_offset   37        /* max buffer size         */
#define SMB_negrLM_mmc_offset   39        /* max mpx count           */
#define SMB_negrLM_mnv_offset   41        /* max number of VCs       */
#define SMB_negrLM_rm_offset    43        /* raw mode support bit vec*/
#define SMB_read_raw_mask       0x01
#define SMB_write_raw_mask      0x02
#define SMB_negrLM_sk_offset    45        /* session key, 32 bits    */
#define SMB_negrLM_st_offset    49        /* Current server time     */
#define SMB_negrLM_sd_offset    51        /* Current server date     */
#define SMB_negrLM_stz_offset   53        /* Server Time Zone        */
#define SMB_negrLM_ekl_offset   55        /* encryption key length   */
#define SMB_negrLM_res_offset   57        /* reserved                */
#define SMB_negrLM_bcc_offset   59        /* bcc                     */
#define SMB_negrLM_len          61        /* 61 bytes ?              */
#define SMB_negrLM_buf_offset   61        /* Where the fun begins    */

#define SMB_negrNTLM_idx_offset 33        /* Selected protocol       */
#define SMB_negrNTLM_sec_offset 35        /* Security more           */
#define SMB_negrNTLM_mmc_offset 36        /* Different format above  */
#define SMB_negrNTLM_mnv_offset 38        /* Max VCs                 */
#define SMB_negrNTLM_mbs_offset 40        /* MBS now a long          */
#define SMB_negrNTLM_mrs_offset 44        /* Max raw size            */
#define SMB_negrNTLM_sk_offset  48        /* Session Key             */
#define SMB_negrNTLM_cap_offset 52        /* Capabilities            */
#define SMB_negrNTLM_stl_offset 56        /* Server time low         */
#define SMB_negrNTLM_sth_offset 60        /* Server time high        */
#define SMB_negrNTLM_stz_offset 64        /* Server time zone        */
#define SMB_negrNTLM_ekl_offset 66        /* Encrypt key len         */
#define SMB_negrNTLM_bcc_offset 67        /* Bcc                     */
#define SMB_negrNTLM_len        69
#define SMB_negrNTLM_buf_offset 69

/* Offsets related to Tree Connect                                      */

#define SMB_tcon_bcc_offset     33
#define SMB_tcon_buf_offset     35        /* where the data is for tcon */
#define SMB_tcon_len            35        /* plus the data              */

#define SMB_tconr_mbs_offset    33        /* max buffer size         */
#define SMB_tconr_tid_offset    35        /* returned tree id        */
#define SMB_tconr_bcc_offset    37
#define SMB_tconr_len           39

#define SMB_tconx_axc_offset    33        /* And X Command                */
#define SMB_tconx_axr_offset    34        /* reserved                     */
#define SMB_tconx_axo_offset    35        /* Next command offset          */
#define SMB_tconx_flg_offset    37        /* Flags, bit0=1 means disc TID */
#define SMB_tconx_pwl_offset    39        /* Password length              */
#define SMB_tconx_bcc_offset    41        /* bcc                          */
#define SMB_tconx_buf_offset    43        /* buffer                       */
#define SMB_tconx_len           43        /* up to data ...               */

#define SMB_tconxr_axc_offset   33        /* Where the AndX Command is    */
#define SMB_tconxr_axr_offset   34        /* Reserved                     */
#define SMB_tconxr_axo_offset   35        /* AndX offset location         */

/* Offsets related to tree_disconnect                                  */

#define SMB_tdis_bcc_offset     33        /* bcc                     */
#define SMB_tdis_len            35        /* total len               */

#define SMB_tdisr_bcc_offset    33        /* bcc                     */
#define SMB_tdisr_len           35

/* Offsets related to Open Request                                     */

#define SMB_open_mod_offset     33        /* Mode to open with       */
#define SMB_open_atr_offset     35        /* Attributes of file      */
#define SMB_open_bcc_offset     37        /* bcc                     */
#define SMB_open_buf_offset     39        /* File name               */
#define SMB_open_len            39        /* Plus the file name      */

#define SMB_openx_axc_offset    33        /* Next command            */
#define SMB_openx_axr_offset    34        /* Reserved                */
#define SMB_openx_axo_offset    35        /* offset of next wct      */
#define SMB_openx_flg_offset    37        /* Flags, bit0 = need more info */
/* bit1 = exclusive oplock */
/* bit2 = batch oplock     */
#define SMB_openx_mod_offset    39        /* mode to open with       */
#define SMB_openx_atr_offset    41        /* search attributes       */
#define SMB_openx_fat_offset    43        /* File attributes         */
#define SMB_openx_tim_offset    45        /* time and date of creat  */
#define SMB_openx_ofn_offset    49        /* Open function           */
#define SMB_openx_als_offset    51        /* Space to allocate on    */
#define SMB_openx_res_offset    55        /* reserved                */
#define SMB_openx_bcc_offset    63        /* bcc                     */
#define SMB_openx_buf_offset    65        /* Where file name goes    */
#define SMB_openx_len           65

#define SMB_openr_fid_offset    33        /* FID returned            */
#define SMB_openr_atr_offset    35        /* Attributes opened with  */
#define SMB_openr_tim_offset    37        /* Last mod time of file   */
#define SMB_openr_fsz_offset    41        /* File size 4 bytes       */
#define SMB_openr_acc_offset    45        /* Access allowed          */
#define SMB_openr_bcc_offset    47
#define SMB_openr_len           49

#define SMB_openxr_axc_offset   33        /* And X command           */
#define SMB_openxr_axr_offset   34        /* reserved                */
#define SMB_openxr_axo_offset   35        /* offset to next command  */
#define SMB_openxr_fid_offset   37        /* FID returned            */
#define SMB_openxr_fat_offset   39        /* File attributes returned*/
#define SMB_openxr_tim_offset   41        /* File creation date etc  */
#define SMB_openxr_fsz_offset   45        /* Size of file            */
#define SMB_openxr_acc_offset   49        /* Access granted          */

#define SMB_clos_fid_offset     33        /* FID to close            */
#define SMB_clos_tim_offset     35        /* Last mod time           */
#define SMB_clos_bcc_offset     39        /* bcc                     */
#define SMB_clos_len            41

/* Offsets related to Write requests                                 */

#define SMB_write_fid_offset    33        /* FID to write            */
#define SMB_write_cnt_offset    35        /* bytes to write          */
#define SMB_write_ofs_offset    37        /* location to write to    */
#define SMB_write_clf_offset    41        /* advisory count left     */
#define SMB_write_bcc_offset    43        /* bcc = data bytes + 3    */
#define SMB_write_buf_offset    45        /* Data=0x01, len, data    */
#define SMB_write_len           45        /* plus the data ...       */

#define SMB_writr_cnt_offset    33        /* Count of bytes written  */
#define SMB_writr_bcc_offset    35        /* bcc                     */
#define SMB_writr_len           37

/* Offsets related to read requests */

#define SMB_read_fid_offset     33        /* FID of file to read     */
#define SMB_read_cnt_offset     35        /* count of words to read  */
#define SMB_read_ofs_offset     37        /* Where to read from      */
#define SMB_read_clf_offset     41        /* Advisory count to go    */
#define SMB_read_bcc_offset     43
#define SMB_read_len            45

#define SMB_readr_cnt_offset    33        /* Count of bytes returned */
#define SMB_readr_res_offset    35        /* 4 shorts reserved, 8 bytes */
#define SMB_readr_bcc_offset    43        /* bcc                     */
#define SMB_readr_bff_offset    45        /* buffer format char = 0x01 */
#define SMB_readr_len_offset    46        /* buffer len              */
#define SMB_readr_len           45        /* length of the readr before data */

/* Offsets for Create file                                           */

#define SMB_creat_atr_offset    33        /* Attributes of new file ... */
#define SMB_creat_tim_offset    35        /* Time of creation           */
#define SMB_creat_dat_offset    37        /* 4004BCE :-)                */
#define SMB_creat_bcc_offset    39        /* bcc                        */
#define SMB_creat_buf_offset    41
#define SMB_creat_len           41        /* Before the data            */

#define SMB_creatr_fid_offset   33        /* FID of created file        */

/* Offsets for Delete file                                           */

#define SMB_delet_sat_offset    33        /* search attribites          */
#define SMB_delet_bcc_offset    35        /* bcc                        */
#define SMB_delet_buf_offset    37
#define SMB_delet_len           37

/* Offsets for SESSION_SETUP_ANDX for both LM and NT LM protocols    */

#define SMB_ssetpLM_mbs_offset  37        /* Max buffer Size, allow for AndX */
#define SMB_ssetpLM_mmc_offset  39        /* max multiplex count             */
#define SMB_ssetpLM_vcn_offset  41        /* VC number if new VC             */
#define SMB_ssetpLM_snk_offset  43        /* Session Key                     */
#define SMB_ssetpLM_pwl_offset  47        /* password length                 */
#define SMB_ssetpLM_res_offset  49        /* reserved                        */
#define SMB_ssetpLM_bcc_offset  53        /* bcc                             */
#define SMB_ssetpLM_len         55        /* before data ...                 */
#define SMB_ssetpLM_buf_offset  55

#define SMB_ssetpNTLM_mbs_offset 37       /* Max Buffer Size for NT LM 0.12  */
/* and above                       */
#define SMB_ssetpNTLM_mmc_offset 39       /* Max Multiplex count             */
#define SMB_ssetpNTLM_vcn_offset 41       /* VC Number                       */
#define SMB_ssetpNTLM_snk_offset 43       /* Session key                     */
#define SMB_ssetpNTLM_cipl_offset 47      /* Case Insensitive PW Len         */
#define SMB_ssetpNTLM_cspl_offset 49      /* Unicode pw len                  */
#define SMB_ssetpNTLM_res_offset 51       /* reserved                        */
#define SMB_ssetpNTLM_cap_offset 55       /* server capabilities             */
#define SMB_ssetpNTLM_bcc_offset 59       /* bcc                             */
#define SMB_ssetpNTLM_len        61       /* before data                     */
#define SMB_ssetpNTLM_buf_offset 61

#define SMB_ssetpr_axo_offset  35         /* Offset of next response ...    */
#define SMB_ssetpr_act_offset  37         /* action, bit 0 = 1 => guest     */
#define SMB_ssetpr_bcc_offset  39         /* bcc                            */
#define SMB_ssetpr_buf_offset  41         /* Native OS etc                  */

/* Offsets for SMB create directory                                         */

#define SMB_creatdir_bcc_offset 33        /* only a bcc here                */
#define SMB_creatdir_buf_offset 35        /* Where things start             */
#define SMB_creatdir_len        35

/* Offsets for SMB delete directory                                         */

#define SMB_deletdir_bcc_offset 33        /* only a bcc here                */
#define SMB_deletdir_buf_offset 35        /* where things start             */
#define SMB_deletdir_len        35

/* Offsets for SMB check directory                                          */

#define SMB_checkdir_bcc_offset 33        /* Only a bcc here                */
#define SMB_checkdir_buf_offset 35        /* where things start             */
#define SMB_checkdir_len        35

/* Offsets for SMB search                                                   */

#define SMB_search_mdc_offset   33        /* Max Dir ents to return         */
#define SMB_search_atr_offset   35        /* Search attributes              */
#define SMB_search_bcc_offset   37        /* bcc                            */
#define SMB_search_buf_offset   39        /* where the action is            */
#define SMB_search_len          39

#define SMB_searchr_dec_offset  33        /* Dir ents returned              */
#define SMB_searchr_bcc_offset  35        /* bcc                            */
#define SMB_searchr_buf_offset  37        /* Where the action starts        */
#define SMB_searchr_len         37        /* before the dir ents            */

#define SMB_searchr_dirent_len  43        /* 53 bytes                       */

/* Defines for SMB transact and transact2 calls                             */

#define SMB_trans_tpc_offset    33        /* Total param count              */
#define SMB_trans_tdc_offset    35        /* total Data count               */
#define SMB_trans_mpc_offset    37        /* Max params bytes to return     */
#define SMB_trans_mdc_offset    39        /* Max data bytes to return       */
#define SMB_trans_msc_offset    41        /* Max setup words to return      */
#define SMB_trans_rs1_offset    42        /* Reserved byte                  */
#define SMB_trans_flg_offset    43        /* flags                          */
#define SMB_trans_tmo_offset    45        /* Timeout, long                  */
#define SMB_trans_rs2_offset    49        /* Next reserved                  */
#define SMB_trans_pbc_offset    51        /* Param Byte count in buf        */
#define SMB_trans_pbo_offset    53        /* Offset to param bytes          */
#define SMB_trans_dbc_offset    55        /* Data byte count in buf         */
#define SMB_trans_dbo_offset    57        /* Data byte offset               */
#define SMB_trans_suc_offset    59        /* Setup count - byte             */
#define SMB_trans_rs3_offset    60        /* Reserved to pad ...            */
#define SMB_trans_len           61        /* Up to setup, still need bcc    */

#define SMB_transr_tpc_offset   33        /* Total param bytes returned     */
#define SMB_transr_tdc_offset   35
#define SMB_transr_rs1_offset   37
#define SMB_transr_pbc_offset   39
#define SMB_transr_pbo_offset   41
#define SMB_transr_pdi_offset   43        /* parameter displacement         */
#define SMB_transr_dbc_offset   45
#define SMB_transr_dbo_offset   47
#define SMB_transr_ddi_offset   49
#define SMB_transr_suc_offset   51
#define SMB_transr_rs2_offset   52
#define SMB_transr_len          53

/* Bit masks for SMB Capabilities ...                       */

#define SMB_cap_raw_mode         0x0001
#define SMB_cap_mpx_mode         0x0002
#define SMB_cap_unicode          0x0004
#define SMB_cap_large_files      0x0008
#define SMB_cap_nt_smbs          0x0010
#define SMB_rpc_remote_apis      0x0020
#define SMB_cap_nt_status        0x0040
#define SMB_cap_level_II_oplocks 0x0080
#define SMB_cap_lock_and_read    0x0100
#define SMB_cap_nt_find          0x0200

/* SMB LANMAN api call defines */

#define SMB_LMapi_SetUserInfo     0x0072
#define SMB_LMapi_UserPasswordSet 0x0073

/* Structures and defines we use in the client interface */

/* The protocols we might support. Perhaps a bit ambitious, as only RFCNB */
/* has any support so far 0(sometimes called NBT)                         */

typedef enum {SMB_RFCNB, SMB_IPXNB, SMB_NETBEUI, SMB_X25} SMB_Transport_Types;

typedef enum {SMB_Con_FShare, SMB_Con_PShare, SMB_Con_IPC} SMB_Con_Types;

typedef enum {SMB_State_NoState, SMB_State_Stopped, SMB_State_Started} SMB_State_Types;

/* The following two arrays need to be in step!              */
/* We must make it possible for callers to specify these ... */

extern int SMB_Types[];

typedef struct SMB_Status {

    union {
        struct {
            unsigned char ErrorClass;
            unsigned char Reserved;
            unsigned short Error;
        } DosError;
        unsigned int NtStatus;
    } status;
} SMB_Status;

#define SMBLIB_DEFAULT_DOMAIN "SMBlib_dom"
#define SMBLIB_DEFAULT_OSNAME "UNIX of some type"
#define SMBLIB_DEFAULT_LMTYPE "SMBlib LM2.1 minus a bit"
#define SMBLIB_MAX_XMIT 65535

#define SMB_Sec_Mode_Share 0
#define SMB_Sec_Mode_User  1

typedef struct SMB_File_Def SMB_File;

struct SMB_File_Def {

    SMB_Tree_Handle tree;
    char filename[256];          /* We should malloc this ... */
    UWORD fid;
    unsigned int lastmod;
    unsigned int size;           /* Could blow up if 64bit files supported */
    UWORD access;
    off_t fileloc;

};

/* global Variables for the library */

extern SMB_State_Types SMBlib_State;

#ifndef SMBLIB_ERRNO
extern int SMBlib_errno;
extern int SMBlib_SMB_Error;          /* last Error             */
#endif

void SMB_Get_My_Name(char *name, int len);

#endif /* _SMBLIB_PRIV_H_ */

