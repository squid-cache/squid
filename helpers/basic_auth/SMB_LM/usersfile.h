/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

typedef struct {
    char *path;
    char **names;
    int Alloc;
    int Inuse;
    time_t LMT;
} usersfile;

int Read_usersfile(const char *path, usersfile * uf);
int Check_userlist(usersfile * uf, char *User);
void Check_forfilechange(usersfile * uf);
