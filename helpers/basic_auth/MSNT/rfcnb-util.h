/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 * 
 * Version 1.0
 * RFCNB Utility Defines
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

void RFCNB_CvtPad_Name(char *name1, char *name2);

void RFCNB_AName_To_NBName(char *AName, char *NBName);

void RFCNB_NBName_To_AName(char *NBName, char *AName);

void RFCNB_Print_Hex(FILE * fd, struct RFCNB_Pkt *pkt, int Offset, int Len);

struct RFCNB_Pkt *RFCNB_Alloc_Pkt(int n);

void RFCNB_Print_Pkt(FILE * fd, char *dirn, struct RFCNB_Pkt *pkt, int len);

int RFCNB_Name_To_IP(char *host, struct in_addr *Dest_IP);

int RFCNB_Close(int socket);

int RFCNB_IP_Connect(struct in_addr Dest_IP, int port);

int RFCNB_Session_Req(RFCNB_Con * con,
    char *Called_Name,
    char *Calling_Name,
    BOOL * redirect,
    struct in_addr *Dest_IP,
    int *port);

void RFCNB_Free_Pkt(struct RFCNB_Pkt *pkt);
