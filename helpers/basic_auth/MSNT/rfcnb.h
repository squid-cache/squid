/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 *
 * Version 1.0
 * RFCNB Defines
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

/* Error responses */

#include "rfcnb-error.h"
#include "rfcnb-common.h"

/* Defines we need */

#define RFCNB_Default_Port 139

/* Definition of routines we define */

struct RFCNB_Con;

void *RFCNB_Call(char *Called_Name, char *Calling_Name, char *Called_Address,
                 int port);

int RFCNB_Send(struct RFCNB_Con *Con_Handle, struct RFCNB_Pkt *Data, int Length);

int RFCNB_Recv(struct RFCNB_Con *Con_Handle, struct RFCNB_Pkt *Data, int Length);

int RFCNB_Hangup(struct RFCNB_Con *Con_Handle);

void RFCNB_Get_Error(char *buffer, int buf_len);
int RFCNB_Get_Last_Error(void);
int RFCNB_Get_Last_Errno(void);
void RFCNB_Get_Error_Msg(int code, char *msg_buf, int len);

