/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX SMBlib NetBIOS implementation

   Version 1.0
   SMBlib File Access Routines

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

/* Open a file with file_name using desired mode and search attr  */
/* If File_Handle is null, then create and populate a file handle */

SMB_File *SMB_Open(SMB_Tree_Handle Tree_Handle,
                   SMB_File *File_Handle,
                   char *file_name,
                   WORD mode,
                   WORD search)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;
    struct SMB_File_Def *file_tmp;

    /* We allocate a file object and copy some things ... */

    file_tmp = File_Handle;

    if (File_Handle == NULL) {

        if ((file_tmp = (SMB_File *)malloc(sizeof(SMB_File))) == NULL) {

#ifdef DEBUG
            fprintf(stderr, "Could not allocate file handle space ...");
#endif

            SMBlib_errno = SMBlibE_NoSpace;
            return(NULL);

        }

    }

    strncpy(file_tmp -> filename, file_name, sizeof(file_tmp -> filename) - 1);
    file_tmp -> tree = Tree_Handle;
    file_tmp -> fid = 0xFFFF;  /* Is this an invalid FID? */

    param_len = strlen(file_name) + 2; /* 1 for null, 1 for ASCII marker */

    pkt_len = SMB_open_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(max(pkt_len, SMB_openr_len));

    if (pkt == NULL) { /* Really should do some error handling */

        if (File_Handle == NULL)
            free(file_tmp);
        SMBlib_errno = SMBlibE_NoSpace;
        return(NULL);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_open_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBopen;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Tree_Handle -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, Tree_Handle -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Tree_Handle -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Tree_Handle -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 2;

    SSVAL(SMB_Hdr(pkt), SMB_open_mod_offset, mode);
    SSVAL(SMB_Hdr(pkt), SMB_open_atr_offset, search);
    SSVAL(SMB_Hdr(pkt), SMB_open_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_open_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, file_name);
    p = p + strlen(file_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Open request\n");
#endif

        if (File_Handle == NULL)
            free(file_tmp);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(NULL);

    }

    /* Now get the response ... */

#ifdef DEBUG
    fprintf(stderr, "Pkt_Len for Open resp = %i\n", pkt_len);
#endif

    if (RFCNB_Recv(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to open request\n");
#endif

        if (File_Handle = NULL)
            free(file_tmp);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(NULL);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Open failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        if (File_Handle = NULL)
            free(file_tmp);
        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(NULL);      /* Should clean up ... */

    }

    file_tmp -> fid     = SVAL(SMB_Hdr(pkt), SMB_openr_fid_offset);
    file_tmp -> lastmod = IVAL(SMB_Hdr(pkt), SMB_openr_tim_offset);
    file_tmp -> size    = IVAL(SMB_Hdr(pkt), SMB_openr_fsz_offset);
    file_tmp -> access  = SVAL(SMB_Hdr(pkt), SMB_openr_acc_offset);
    file_tmp -> fileloc = 0;

    RFCNB_Free_Pkt(pkt); /* Free up this space  */

#ifdef DEBUG
    fprintf(stderr, "SMB_Open succeeded, FID = %i\n", file_tmp -> fid);
#endif

    RFCNB_Free_Pkt(pkt);

    return(file_tmp);

}

/* Close the file referred to in File_Handle */

int SMB_Close(SMB_File *File_Handle)

{
    struct SMB_Close_Prot_Def *prot_pkt;
    struct SMB_Hdr_Def_LM12 *resp_pkt;
    struct RFCNB_Pkt *pkt;
    int pkt_len;

    if (File_Handle == NULL) { /* Error */

        /*SMBLIB_errno = SMBLIBE_BadHandle; */
        return(-1);

    }

    pkt_len = SMB_clos_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_clos_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBclose;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, File_Handle -> tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, File_Handle -> tree ->  tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, File_Handle -> tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, File_Handle -> tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 3;

    SSVAL(SMB_Hdr(pkt), SMB_clos_fid_offset, File_Handle -> fid);
    SIVAL(SMB_Hdr(pkt), SMB_clos_tim_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_clos_bcc_offset, 0);

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(File_Handle -> tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Open request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(File_Handle -> tree -> con ->  Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to open request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Close failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

#ifdef DEBUG
    fprintf(stderr, "File %s closed successfully.\n", File_Handle -> filename);
#endif DEBUG

    /* We should deallocate the File_Handle now ... */

    File_Handle -> tree = NULL;
    File_Handle -> filename[0] = 0;
    File_Handle -> fid = 0xFFFF;

    RFCNB_Free_Pkt(pkt);
    free(File_Handle);

    return(0);
}

/* Read numbytes into data from the file pointed to by File_Handle from */
/* the offset in the File_Handle.                                       */

int SMB_Read(SMB_File *File_Handle, char *data, int numbytes)

{
    int tot_read;
    struct RFCNB_Pkt *snd_pkt, *recv_pkt, *data_ptr;
    int snd_pkt_len, recv_pkt_len, this_read, bytes_left = numbytes;
    int max_read_data, bytes_read = 0;

    /* We loop around, reading the data, accumulating it into the buffer */
    /* We build an SMB packet, where the data is pointed to by a fragment*/
    /* tagged onto the end                                               */

    data_ptr = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(0);
    if (data_ptr == NULL) {

        /* We should handle the error here */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    snd_pkt_len = SMB_read_len;        /* size for the read SMB */
    recv_pkt_len = SMB_readr_len + 3;  /* + 3 for the datablockID and blklen */

    snd_pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(snd_pkt_len);

    if (snd_pkt == NULL) {

        RFCNB_Free_Pkt(data_ptr);
        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    recv_pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(recv_pkt_len);

    if (recv_pkt == NULL) {

        RFCNB_Free_Pkt(snd_pkt);
        RFCNB_Free_Pkt(data_ptr);
        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Put the recv pkt together */

    recv_pkt -> next = data_ptr;

    /* Now build the read request and the receive packet etc ... */

    memset(SMB_Hdr(snd_pkt), 0, SMB_read_len);
    SIVAL(SMB_Hdr(snd_pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(snd_pkt) + SMB_hdr_com_offset) = SMBread;
    SSVAL(SMB_Hdr(snd_pkt), SMB_hdr_pid_offset, File_Handle -> tree -> con -> pid);
    SSVAL(SMB_Hdr(snd_pkt), SMB_hdr_tid_offset, File_Handle -> tree -> tid);
    SSVAL(SMB_Hdr(snd_pkt), SMB_hdr_mid_offset, File_Handle -> tree -> con -> mid);
    SSVAL(SMB_Hdr(snd_pkt), SMB_hdr_uid_offset, File_Handle -> tree -> con -> uid);
    *(SMB_Hdr(snd_pkt) + SMB_hdr_wct_offset) = 5;
    SSVAL(SMB_Hdr(snd_pkt), SMB_read_fid_offset, File_Handle -> fid);

    max_read_data = (File_Handle -> tree -> mbs) - recv_pkt_len;

    while (bytes_left > 0)  {

        this_read = (bytes_left > max_read_data?max_read_data: bytes_left);

        SSVAL(SMB_Hdr(snd_pkt), SMB_read_cnt_offset, this_read);
        SIVAL(SMB_Hdr(snd_pkt), SMB_read_ofs_offset, File_Handle -> fileloc);
        SSVAL(SMB_Hdr(snd_pkt), SMB_read_clf_offset, 0x0);
        SSVAL(SMB_Hdr(snd_pkt), SMB_read_bcc_offset, 0x0);

        /* Now send the packet and wait for a response */

        if (RFCNB_Send(File_Handle -> tree -> con -> Trans_Connect, snd_pkt, snd_pkt_len) < 0) {

#ifdef DEBUG
            fprintf(stderr, "Error sending read request\n");
#endif

            data_ptr -> data = NULL;
            data_ptr -> len = 0;
            RFCNB_Free_Pkt(recv_pkt);
            RFCNB_Free_Pkt(snd_pkt);
            SMBlib_errno = SMBlibE_SendFailed;
            return(SMBlibE_BAD);

        }

        /* Now get the response ... first point the data portion to the right */
        /* place in the read buffer ... what we are doing is ugly             */

        data_ptr -> data = (data + bytes_read);
        data_ptr -> len = this_read;

        if (RFCNB_Recv(File_Handle -> tree -> con -> Trans_Connect, recv_pkt, recv_pkt_len + this_read) < 0) {

#ifdef DEBUG
            fprintf(stderr, "Error receiving response to write\n");
#endif

            data_ptr -> len = 0;
            data_ptr -> data = NULL;
            RFCNB_Free_Pkt(recv_pkt);
            RFCNB_Free_Pkt(snd_pkt);
            SMBlib_errno = SMBlibE_RecvFailed;
            return(SMBlibE_BAD);

        }

        if (CVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
            fprintf(stderr, "SMB_Read failed with errorclass = %i, Error Code = %i\n",
                    CVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset),
                    SVAL(SMB_Hdr(recv_pkt), SMB_hdr_err_offset));
#endif

            SMBlib_SMB_Error = IVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset);
            data_ptr -> data = NULL;
            data_ptr -> len = 0;
            RFCNB_Free_Pkt(recv_pkt);
            RFCNB_Free_Pkt(snd_pkt);
            SMBlib_errno = SMBlibE_Remote;
            return(-1);

        }

        /* Ok, that worked, so update some things here ... */

        bytes_read = bytes_read + SVAL(SMB_Hdr(recv_pkt), SMB_readr_cnt_offset);
        bytes_left = bytes_left - SVAL(SMB_Hdr(recv_pkt), SMB_readr_cnt_offset);

    }

    /* Now free those packet headers that we allocated ... */

    data_ptr -> data = NULL;     /* Since recv_pkt points to data_ptr */
    data_ptr -> len = 0;         /* it is freed too                   */
    RFCNB_Free_Pkt(recv_pkt);
    RFCNB_Free_Pkt(snd_pkt);

    return(bytes_read);

}

/* Lseek seeks just like the UNIX version does ...                     */

off_t SMB_Lseek(SMB_File *File_Handle, off_t offset, int whence)

{

    /* We should check that the file handle is kosher ... We may also blow up
       if we get a 64 bit offset ... should avoid wrap-around ... */

    switch (whence) {
    case SEEK_SET:

        File_Handle -> fileloc = offset;
        break;

    case SEEK_CUR:

        File_Handle -> fileloc = File_Handle -> fileloc + offset;
        break;

    case SEEK_END:

        File_Handle -> fileloc = File_Handle -> size + offset;
        break;

    default:
        return(-1);

    }

    return(File_Handle -> fileloc);

}

/* Write numbytes from data to the file pointed to by the File_Handle at */
/* the offset in the File_Handle.                                        */

int SMB_Write(SMB_File *File_Handle, char *data, int numbytes)

{
    int tot_written = 0;
    struct RFCNB_Pkt *pkt, *data_ptr;
    int pkt_len, i, this_write, max_write_data, bytes_left = numbytes;

    /* We loop around, writing the data, accumulating what was written    */
    /* We build an SMB packet, where the data is pointed to by a fragment */
    /* tagged onto the end ...                                            */

    data_ptr = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(0);
    if (data_ptr == NULL) {

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    pkt_len = SMB_write_len + 3;  /* + 3 for the datablockID and blklen */

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) {

        RFCNB_Free_Pkt(data_ptr);
        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now init the things that will be the same across the possibly multiple
       packets to write this data.                                           */

    memset(SMB_Hdr(pkt), 0, SMB_write_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBwrite;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, File_Handle -> tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, File_Handle -> tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, File_Handle -> tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, File_Handle -> tree -> con -> uid);
    SSVAL(SMB_Hdr(pkt), SMB_write_fid_offset, File_Handle -> fid);

    /* We will program this as send/response for the moment, but if we could
       only send the second block before getting the first, we could speed
       things up a bit ...                                                   */

    max_write_data = (File_Handle -> tree -> mbs) - pkt_len;

    /* the 3 is for the data block id and length that precedes the data */

    while (bytes_left > 0) {

        /* bytes to write? */

        this_write = (bytes_left > max_write_data?max_write_data:bytes_left);

        data_ptr -> next = NULL;
        data_ptr -> len = this_write;
        data_ptr -> data = data + tot_written;

        pkt -> next = data_ptr;  /* link the data on the end */

        SSVAL(SMB_Hdr(pkt), SMB_hdr_flg_offset, 0);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 5;
        SSVAL(SMB_Hdr(pkt), SMB_write_fid_offset, File_Handle -> fid);
        SSVAL(SMB_Hdr(pkt), SMB_write_cnt_offset, this_write);
        SIVAL(SMB_Hdr(pkt), SMB_write_ofs_offset, File_Handle -> fileloc);
        SSVAL(SMB_Hdr(pkt), SMB_write_clf_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_write_bcc_offset, (this_write + 3));

        *(SMB_Hdr(pkt) + SMB_write_buf_offset) = SMBdatablockID;
        SSVAL(SMB_Hdr(pkt), SMB_write_buf_offset + 1, this_write);

        /* Now send the packet and wait for a response */

        if (RFCNB_Send(File_Handle -> tree -> con -> Trans_Connect, pkt, pkt_len + this_write) < 0) {

#ifdef DEBUG
            fprintf(stderr, "Error sending write request\n");
#endif

            data_ptr -> next = NULL;
            data_ptr -> len = 0;
            RFCNB_Free_Pkt(pkt);
            SMBlib_errno = -SMBlibE_SendFailed;
            return(-1);

        }

        /* Now get the response ... */

        if (RFCNB_Recv(File_Handle -> tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
            fprintf(stderr, "Error receiving response to write\n");
#endif

            data_ptr -> next = NULL;
            data_ptr -> len = 0;
            RFCNB_Free_Pkt(pkt);
            SMBlib_errno = -SMBlibE_RecvFailed;
            return(-1);

        }

        if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
            fprintf(stderr, "SMB_Write failed with errorclass = %i, Error Code = %i\n",
                    CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                    SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

            SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
            data_ptr -> data = NULL;
            data_ptr -> len = 0;
            RFCNB_Free_Pkt(pkt);
            SMBlib_errno = SMBlibE_Remote;
            return(SMBlibE_BAD);

        }

        /* Ok, that worked, so update some things here ... */

        tot_written = tot_written + this_write;
        bytes_left  = bytes_left - this_write;

        /* Assume that it is ok to update this now, but what about only part */
        /* of the write succeeding?                                          */

        File_Handle -> fileloc = File_Handle -> fileloc + this_write;

#ifdef DEBUG
        fprintf(stderr, "--This_write = %i, bytes_left = %i\n",
                this_write, bytes_left);
#endif

    }

    /* Let's get rid of those packet headers we are using ... */

    data_ptr -> data = NULL;
    pkt -> next = NULL;

    RFCNB_Free_Pkt(pkt);

    return(tot_written);

}

/* Create file on the server with name file_name and attributes search */

SMB_File *SMB_Create(SMB_Tree_Handle Tree_Handle,
                     SMB_File *File_Handle,
                     char *file_name,
                     WORD search)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;
    struct SMB_File_Def *file_tmp;

    /* We allocate a file object and copy some things ... */

    file_tmp = File_Handle;

    if (File_Handle == NULL) {

        if ((file_tmp = (SMB_File *)malloc(sizeof(SMB_File))) == NULL) {

#ifdef DEBUG
            fprintf(stderr, "Could not allocate file handle space ...");
#endif

            SMBlib_errno = SMBlibE_NoSpace;
            return(NULL);

        }

    }

    strncpy(file_tmp -> filename, file_name, sizeof(file_tmp -> filename));
    file_tmp -> tree = Tree_Handle;
    file_tmp -> fid = 0xFFFF;  /* Is this an invalid FID? */

    param_len = strlen(file_name) + 2; /* 1 for null, 1 for ASCII marker */

    pkt_len = SMB_creat_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        if (File_Handle == NULL)
            free(file_tmp);
        SMBlib_errno = SMBlibE_NoSpace;
        return(NULL);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_creat_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBcreate;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Tree_Handle -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, Tree_Handle -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Tree_Handle -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Tree_Handle -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 3;

    SSVAL(SMB_Hdr(pkt), SMB_creat_atr_offset, search);
    SSVAL(SMB_Hdr(pkt), SMB_creat_tim_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_creat_dat_offset, 0);
    SSVAL(SMB_Hdr(pkt), SMB_creat_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_creat_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, file_name);
    p = p + strlen(file_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Open request\n");
#endif

        if (File_Handle == NULL)
            free(file_tmp);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(NULL);

    }

    /* Now get the response ... */

#ifdef DEBUG
    fprintf(stderr, "Pkt_Len for Create resp = %i\n", pkt_len);
#endif

    if (RFCNB_Recv(Tree_Handle -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to create request\n");
#endif

        if (File_Handle == NULL)
            free(file_tmp);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(NULL);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Create failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        if (File_Handle == NULL)
            free(file_tmp);
        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(NULL);      /* Should clean up ... */

    }

    file_tmp -> fid     = SVAL(SMB_Hdr(pkt), SMB_creatr_fid_offset);
    file_tmp -> lastmod = 0;
    file_tmp -> size    = 0;
    file_tmp -> access  = SMB_AMODE_OPENRW;
    file_tmp -> fileloc = 0;

    RFCNB_Free_Pkt(pkt); /* Free up this space  */

#ifdef DEBUG
    fprintf(stderr, "SMB_Create succeeded, FID = %i\n", file_tmp -> fid);
#endif

    return(file_tmp);

}

/* Delete the file passed in as file_name.                              */

int SMB_Delete(SMB_Tree_Handle tree, char *file_name, WORD search)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;

    param_len = strlen(file_name) + 2;
    pkt_len = SMB_delet_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_delet_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBunlink;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 1;

    SIVAL(SMB_Hdr(pkt), SMB_delet_sat_offset, search);
    SSVAL(SMB_Hdr(pkt), SMB_delet_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_delet_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, file_name);
    p = p + strlen(file_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Delete request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con ->  Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to delete request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Delete failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

#ifdef DEBUG
    fprintf(stderr, "File %s deleted successfully.\n", file_name);
#endif DEBUG

    RFCNB_Free_Pkt(pkt);

    return(0);
}

/* Create the directory passed in as dir_name                          */

int SMB_Create_Dir(SMB_Tree_Handle tree, char *dir_name)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;

    param_len = strlen(dir_name) + 2;  /* + null and + asciiID */
    pkt_len = SMB_creatdir_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_creatdir_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBmkdir;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_creatdir_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_creatdir_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, dir_name);
    p = p + strlen(dir_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Create Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con ->  Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Create Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Create_Dir failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

#ifdef DEBUG
    fprintf(stderr, "Directory %s created successfully.\n", dir_name);
#endif DEBUG

    RFCNB_Free_Pkt(pkt);

    return(0);
}

/* Delete the directory passed as dir_name, as long as it is empty ... */

int SMB_Delete_Dir(SMB_Tree_Handle tree, char *dir_name)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;

    param_len = strlen(dir_name) + 2;  /* + null and + asciiID */
    pkt_len = SMB_deletdir_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_deletdir_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBrmdir;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_deletdir_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_deletdir_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, dir_name);
    p = p + strlen(dir_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Delete Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con ->  Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Delete Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Delete_Dir failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

#ifdef DEBUG
    fprintf(stderr, "Directory %s deleted successfully.\n", dir_name);
#endif DEBUG

    RFCNB_Free_Pkt(pkt);

    return(0);
}

/* Check for the existence of the directory in dir_name                    */

int SMB_Check_Dir(SMB_Tree_Handle tree, char *dir_name)

{
    struct RFCNB_Pkt *pkt;
    int pkt_len, param_len;
    char *p;

    param_len = strlen(dir_name) + 2;  /* + null and + asciiID */
    pkt_len = SMB_checkdir_len + param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_checkdir_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBchkpth;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);
    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 0;

    SSVAL(SMB_Hdr(pkt), SMB_checkdir_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_checkdir_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, dir_name);
    p = p + strlen(dir_name);
    *(p+1) = 0;                     /* plug in a null ... */

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending Check Dir Path request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con ->  Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Check Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Check_Dir failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

#ifdef DEBUG
    fprintf(stderr, "Directory %s checked successfully.\n", dir_name);
#endif DEBUG

    RFCNB_Free_Pkt(pkt);

    return(0);
}

/* Search directory for the files listed ... Relative to the TID in the */
/* Con Handle. Return number of Dir Ents returned as the result.        */

int SMB_Search(SMB_Tree_Handle tree,
               char *dir_name,
               WORD search,
               SMB_CP_dirent *dirents,
               int direntc,
               char *resumekey,
               int resumekey_len)

{
    struct RFCNB_Pkt *pkt, *recv_pkt;
    int pkt_len, param_len, recv_param_len, recv_pkt_len, ret_count, i;
    char *p;

    param_len = strlen(dir_name) + 2 + resumekey_len + 3; /* You have to know */
    pkt_len = SMB_search_len + param_len;

    recv_param_len = direntc * SMB_searchr_dirent_len + 3;
    recv_pkt_len = SMB_searchr_len + recv_param_len;

    pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(pkt_len);

    if (pkt == NULL) { /* Really should do some error handling */

        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    recv_pkt = (struct RFCNB_Pkt *)RFCNB_Alloc_Pkt(recv_pkt_len);

    if (recv_pkt == NULL) { /* Really should do some error handling */

        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_NoSpace;
        return(SMBlibE_BAD);

    }

    /* Now plug in the bits we need */

    memset(SMB_Hdr(pkt), 0, SMB_search_len);
    SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);  /* Plunk in IDF */
    *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsearch;
    SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, tree -> con -> pid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, tree -> tid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, tree -> con -> mid);
    SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, tree -> con -> uid);

    /* Tell server we known about non-dos names and extended attributes */

    SSVAL(SMB_Hdr(pkt), SMB_hdr_flg2_offset,
          (SMB_FLG2_NON_DOS | SMB_FLG2_EXT_ATR));

    *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 2;

    SSVAL(SMB_Hdr(pkt), SMB_search_mdc_offset, direntc);  /* How many we want */
    SSVAL(SMB_Hdr(pkt), SMB_search_atr_offset, search);
    SSVAL(SMB_Hdr(pkt), SMB_search_bcc_offset, param_len);

    /* Now plug in the file name ... */

    p = (char *)(SMB_Hdr(pkt) + SMB_search_buf_offset);
    *p = SMBasciiID;
    strcpy(p+1, dir_name);
    p = p + strlen(dir_name) + 2;  /* Skip the null */

    *p = SMBvariableblockID;
    p = p + 1;

    /* And now the resume key */

    SSVAL(p, 0, resumekey_len);

    p = p + 2;

    bcopy(resumekey, p, resumekey_len);

    /* Now send the packet and get the response ... */

    if (RFCNB_Send(tree -> con -> Trans_Connect, pkt, pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error sending search request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        RFCNB_Free_Pkt(recv_pkt);
        SMBlib_errno = -SMBlibE_SendFailed;
        return(SMBlibE_BAD);

    }

    /* Now get the response ... */

    if (RFCNB_Recv(tree -> con ->  Trans_Connect, recv_pkt, recv_pkt_len) < 0) {

#ifdef DEBUG
        fprintf(stderr, "Error receiving response to Check Dir request\n");
#endif

        RFCNB_Free_Pkt(pkt);
        RFCNB_Free_Pkt(recv_pkt);
        SMBlib_errno = -SMBlibE_RecvFailed;
        return(SMBlibE_BAD);

    }

    /* Now parse the response and pass back any error ... */

    if (CVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {  /* Process error */

#ifdef DEBUG
        fprintf(stderr, "SMB_Check_Dir failed with errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(recv_pkt), SMB_hdr_err_offset));
#endif

        SMBlib_SMB_Error = IVAL(SMB_Hdr(recv_pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        RFCNB_Free_Pkt(recv_pkt);
        SMBlib_errno = SMBlibE_Remote;
        return(SMBlibE_BAD);      /* Should clean up ... */

    }

    /* Now copy the results into the user's structure */

    ret_count = SVAL(SMB_Hdr(recv_pkt), SMB_searchr_dec_offset);

    p = SMB_Hdr(recv_pkt) + SMB_searchr_buf_offset + 3;

    /* Hmmm, should check that we have the right number of bytes ... */

    for (i = 0; i < ret_count; i++) {

        bcopy(p, dirents[i].resume_key, 21);

        p = p + 21;

        dirents[i].file_attributes = (unsigned char)*p;

        p = p + 1;

        dirents[i].date_time = IVAL(p, 0); /* Should this be IVAL? */

        p = p + 4;

        dirents[i].size = IVAL(p, 0);

        p = p + 4;

        bcopy(p, dirents[i].filename, 13); /* Copy in file name */

        p = p + 13;

    }

    return(ret_count);

}

