/* UNIX SMBlib NetBIOS implementation
 * 
 * Version 1.0
 * SMBlib Defines
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

#include "std-defines.h"
#include "smblib-common.h"

/* Just define all the entry points */

/* Create a handle to allow us to set/override some parameters ...       */

void *SMB_Create_Con_Handle();

/* Connect to a server, but do not do a tree con etc ... */

void *SMB_Connect_Server(void *Con, char *server, char *NTdomain);

/* Connect to a server and give us back a handle. If Con == NULL, create */
/* The handle and populate it with defaults                              */

void *SMB_Connect(void *Con, void **tree,
    char *name, char *User, char *Password);

/* Negotiate a protocol                                                  */

int SMB_Negotiate(void *Con_Handle, char *Prots[]);

/* Connect to a tree ...                                                 */

void *SMB_TreeConnect(void *con_handle, void *tree_handle,
    char *path, char *password, char *dev);

/* Disconnect a tree ...                                                 */

int SMB_TreeDisconect(void *tree_handle);

/* Open a file                                                           */

void *SMB_Open(void *tree_handle,
    void *file_handle,
    char *file_name,
    unsigned short mode,
    unsigned short search);

/* Close a file                                                          */

int SMB_Close(void *file_handle);

/* Disconnect from server. Has flag to specify whether or not we keep the */
/* handle.                                                                */

int SMB_Discon(void *Con, BOOL KeepHandle);

void *SMB_Create(void *Tree_Handle,
    void *File_Handle,
    char *file_name,
    short search);

int SMB_Delete(void *tree, char *file_name, short search);

int SMB_Create_Dir(void *tree, char *dir_name);

int SMB_Delete_Dir(void *tree, char *dir_name);

int SMB_Check_Dir(void *tree, char *dir_name);

int SMB_Get_Last_Error();

int SMB_Get_Last_SMB_Err();

int SMB_Get_Error_Msg(int msg, char *msgbuf, int len);

void *SMB_Logon_And_TCon(void *con, void *tree, char *user, char *pass,
    char *service, char *st);


#define SMBLIB_DEFAULT_DOMAIN "anydom"
