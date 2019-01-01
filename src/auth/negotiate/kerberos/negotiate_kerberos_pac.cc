/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */

#include "squid.h"
#include "rfc1738.h"

#include "negotiate_kerberos.h"

#if HAVE_GSSAPI && HAVE_PAC_SUPPORT

static int bpos;
static krb5_data *ad_data;
static unsigned char *p;

extern int
check_k5_err(krb5_context context, const char *function, krb5_error_code code);

void
align(int n)
{
    if ( bpos % n != 0 ) {
        int al;
        al = (bpos/n);
        bpos = bpos+(bpos-n*al);
    }
}

void
getustr(RPC_UNICODE_STRING *string)
{

    string->length = (uint16_t)((p[bpos]<<0) | (p[bpos+1]<<8));
    string->maxlength = (uint16_t)((p[bpos+2]<<0) | (p[bpos+2+1]<<8));
    string->pointer = (uint32_t)((p[bpos+4]<<0) | (p[bpos+4+1]<<8) | (p[bpos+4+2]<<16) | (p[bpos+4+3]<<24));
    bpos = bpos+8;

}

uint64_t
get6byt_be(void)
{
    uint64_t var;

    var = ((uint64_t)p[bpos+5]<<0) | ((uint64_t)p[bpos+4]<<8) | ((uint64_t)p[bpos+3]<<16) | ((uint64_t)p[bpos+2]<<24) | ((uint64_t)p[bpos+1]<<32) | ((uint64_t)p[bpos]<<40);
    bpos = bpos+6;

    return var;
}

uint32_t
get4byt(void)
{
    uint32_t var;

    var=(uint32_t)((p[bpos]<<0) | (p[bpos+1]<<8) | (p[bpos+2]<<16) | (p[bpos+3]<<24));
    bpos = bpos+4;

    return var;
}

uint16_t
get2byt(void)
{
    uint16_t var;

    var=(uint16_t)((p[bpos]<<0) | (p[bpos+1]<<8));
    bpos = bpos+2;

    return var;
}

uint8_t
get1byt(void)
{
    uint8_t var;

    var=(uint8_t)((p[bpos]<<0));
    bpos = bpos+1;

    return var;
}

char *
pstrcpy( char *src, const char *dst)
{
    if (dst) {
        if (strlen(dst)>MAX_PAC_GROUP_SIZE)
            return NULL;
        else
            return strcpy(src,dst);
    } else
        return src;
}

char *
pstrcat( char *src, const char *dst)
{
    if (dst) {
        if (strlen(src)+strlen(dst)+1>MAX_PAC_GROUP_SIZE)
            return NULL;
        else
            return strcat(src,dst);
    } else
        return src;
}

int
checkustr(RPC_UNICODE_STRING *string)
{

    if (string->pointer != 0) {
        uint32_t size,off,len;
        align(4);
        size = (uint32_t)((p[bpos]<<0) | (p[bpos+1]<<8) | (p[bpos+2]<<16) | (p[bpos+3]<<24));
        bpos = bpos+4;
        off = (uint32_t)((p[bpos]<<0) | (p[bpos+1]<<8) | (p[bpos+2]<<16) | (p[bpos+3]<<24));
        bpos = bpos+4;
        len = (uint32_t)((p[bpos]<<0) | (p[bpos+1]<<8) | (p[bpos+2]<<16) | (p[bpos+3]<<24));
        bpos = bpos+4;
        if (len > size || off != 0 ||
                string->length > string->maxlength || len != string->length/2) {
            debug((char *) "%s| %s: ERROR: RPC_UNICODE_STRING encoding error => size: %d len: %d/%d maxlength: %d offset: %d\n",
                  LogTime(), PROGRAM, size, len, string->length, string->maxlength, off);
            return -1;
        }
        /* UNICODE string */
        bpos = bpos+string->length;
    }
    return 0;
}

char **
getgids(char **Rids, uint32_t GroupIds, uint32_t  GroupCount)
{
    if (GroupIds!= 0) {
        uint32_t ngroup;
        int l;

        align(4);
        ngroup = get4byt();
        if ( ngroup != GroupCount) {
            debug((char *) "%s| %s: ERROR: Group encoding error => GroupCount: %d Array size: %d\n",
                  LogTime(), PROGRAM, GroupCount, ngroup);
            return NULL;
        }
        debug((char *) "%s| %s: INFO: Found %d rids\n", LogTime(), PROGRAM, GroupCount);

        Rids=(char **)xcalloc(GroupCount*sizeof(char*),1);
        for ( l=0; l<(int)GroupCount; l++) {
            uint32_t sauth;
            Rids[l]=(char *)xcalloc(4*sizeof(char),1);
            memcpy((void *)Rids[l],(void *)&p[bpos],4);
            sauth = get4byt();
            debug((char *) "%s| %s: Info: Got rid: %u\n", LogTime(), PROGRAM, sauth);
            /* attribute */
            bpos = bpos+4;
        }
    }
    return Rids;
}

char *
getdomaingids(char *ad_groups, uint32_t DomainLogonId, char **Rids, uint32_t GroupCount)
{
    if (!ad_groups) {
        debug((char *) "%s| %s: ERR: No space to store groups\n",
              LogTime(), PROGRAM);
        return NULL;
    }

    if (DomainLogonId!= 0) {
        uint8_t rev;
        uint64_t idauth;
        char dli[256];
        char *ag;
        int l;

        align(4);

        uint32_t nauth = get4byt();

        // check if nauth math will produce invalid length values on 32-bit
        static uint32_t maxGidCount = (UINT32_MAX-1-1-6)/4;
        if (nauth > maxGidCount) {
            debug((char *) "%s| %s: ERROR: Too many groups ! count > %d : %s\n",
                  LogTime(), PROGRAM, maxGidCount, ad_groups);
            return NULL;
        }
        size_t length = 1+1+6+nauth*4;

        /* prepend rids with DomainID */
        for (l=0; l<(int)GroupCount; l++) {
            ag=(char *)xcalloc((length+4)*sizeof(char),1);
            memcpy((void *)ag,(const void*)&p[bpos],1);
            memcpy((void *)&ag[1],(const void*)&p[bpos+1],1);
            ag[1] = ag[1]+1;
            memcpy((void *)&ag[2],(const void*)&p[bpos+2],6+nauth*4);
            memcpy((void *)&ag[length],(const void*)Rids[l],4);
            if (l==0) {
                if (!pstrcpy(ad_groups,"group=")) {
                    debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                          LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
                }
            } else {
                if (!pstrcat(ad_groups," group=")) {
                    debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                          LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
                }
            }
            struct base64_encode_ctx ctx;
            base64_encode_init(&ctx);
            const uint32_t expectedSz = base64_encode_len(length+4) +1 /* terminator */;
            char *b64buf = static_cast<char *>(xcalloc(expectedSz, 1));
            size_t blen = base64_encode_update(&ctx, b64buf, length+4, reinterpret_cast<uint8_t*>(ag));
            blen += base64_encode_final(&ctx, b64buf+blen);
            b64buf[expectedSz-1] = '\0';
            if (!pstrcat(ad_groups, b64buf)) {
                debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                      LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
            }
            xfree(b64buf);
            xfree(ag);
        }

        /* mainly for debug only */
        rev = get1byt();
        bpos = bpos + 1; /*nsub*/
        idauth = get6byt_be();

        snprintf(dli,sizeof(dli),"S-%d-%lu",rev,(long unsigned int)idauth);
        for ( l=0; l<(int)nauth; l++ ) {
            uint32_t sauth;
            sauth = get4byt();
            snprintf((char *)&dli[strlen(dli)],sizeof(dli)-strlen(dli),"-%u",sauth);
        }
        debug((char *) "%s| %s: INFO: Got DomainLogonId %s\n", LogTime(), PROGRAM, dli);
    }
    return ad_groups;
}

char *
getextrasids(char *ad_groups, uint32_t ExtraSids, uint32_t SidCount)
{
    if (ExtraSids!= 0) {
        uint32_t ngroup;
        uint32_t *pa;
        char *ag;
        int l;

        align(4);
        ngroup = get4byt();
        if ( ngroup != SidCount) {
            debug((char *) "%s| %s: ERROR: Group encoding error => SidCount: %d Array size: %d\n",
                  LogTime(), PROGRAM, SidCount, ngroup);
            return NULL;
        }
        debug((char *) "%s| %s: INFO: Found %d ExtraSIDs\n", LogTime(), PROGRAM, SidCount);

        pa=(uint32_t *)xmalloc(SidCount*sizeof(uint32_t));
        for ( l=0; l < (int)SidCount; l++ ) {
            pa[l] = get4byt();
            bpos = bpos+4; /* attr */
        }

        for ( l=0; l<(int)SidCount; l++ ) {
            char es[256];

            if (pa[l] != 0) {
                uint8_t rev;
                uint64_t idauth;

                uint32_t nauth = get4byt();

                // check if nauth math will produce invalid length values on 32-bit
                static uint32_t maxGidCount = (UINT32_MAX-1-1-6)/4;
                if (nauth > maxGidCount) {
                    debug((char *) "%s| %s: ERROR: Too many extra groups ! count > %d : %s\n",
                          LogTime(), PROGRAM, maxGidCount, ad_groups);
                    xfree(pa);
                    return NULL;
                }

                size_t length = 1+1+6+nauth*4;
                ag = (char *)xcalloc((length)*sizeof(char),1);
                memcpy((void *)ag,(const void*)&p[bpos],length);
                if (!ad_groups) {
                    debug((char *) "%s| %s: ERR: No space to store groups\n",
                          LogTime(), PROGRAM);
                    xfree(pa);
                    xfree(ag);
                    return NULL;
                } else {
                    if (!pstrcat(ad_groups," group=")) {
                        debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                              LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
                    }
                }

                struct base64_encode_ctx ctx;
                base64_encode_init(&ctx);
                const uint32_t expectedSz = base64_encode_len(length) +1 /* terminator */;
                char *b64buf = static_cast<char *>(xcalloc(expectedSz, 1));
                size_t blen = base64_encode_update(&ctx, b64buf, length, reinterpret_cast<uint8_t*>(ag));
                blen += base64_encode_final(&ctx, b64buf+blen);
                b64buf[expectedSz-1] = '\0';
                if (!pstrcat(ad_groups, reinterpret_cast<char*>(b64buf))) {
                    debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                          LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
                }
                xfree(b64buf);
                xfree(ag);

                rev = get1byt();
                bpos = bpos + 1; /* nsub */
                idauth = get6byt_be();

                snprintf(es,sizeof(es),"S-%d-%lu",rev,(long unsigned int)idauth);
                for (int k=0; k<(int)nauth; k++ ) {
                    uint32_t sauth;
                    sauth = get4byt();
                    snprintf((char *)&es[strlen(es)],sizeof(es)-strlen(es),"-%u",sauth);
                }
                debug((char *) "%s| %s: INFO: Got ExtraSid %s\n", LogTime(), PROGRAM, es);
            }
        }
        xfree(pa);
    }
    return ad_groups;
}

char *
get_ad_groups(char *ad_groups, krb5_context context, krb5_pac pac)
{
    krb5_error_code ret;
    RPC_UNICODE_STRING EffectiveName;
    RPC_UNICODE_STRING FullName;
    RPC_UNICODE_STRING LogonScript;
    RPC_UNICODE_STRING ProfilePath;
    RPC_UNICODE_STRING HomeDirectory;
    RPC_UNICODE_STRING HomeDirectoryDrive;
    RPC_UNICODE_STRING LogonServer;
    RPC_UNICODE_STRING LogonDomainName;
    uint32_t GroupCount=0;
    uint32_t GroupIds=0;
    uint32_t LogonDomainId=0;
    uint32_t SidCount=0;
    uint32_t ExtraSids=0;
    /*
    uint32_t ResourceGroupDomainSid=0;
    uint32_t ResourceGroupCount=0;
    uint32_t ResourceGroupIds=0;
    */
    char **Rids=NULL;
    int l=0;

    if (!ad_groups) {
        debug((char *) "%s| %s: ERR: No space to store groups\n",
              LogTime(), PROGRAM);
        return NULL;
    }

    ad_data = (krb5_data *)xcalloc(1,sizeof(krb5_data));

#define KERB_LOGON_INFO 1
    ret = krb5_pac_get_buffer(context, pac, KERB_LOGON_INFO, ad_data);
    if (check_k5_err(context, "krb5_pac_get_buffer", ret))
        goto k5clean;

    p = (unsigned char *)ad_data->data;

    debug((char *) "%s| %s: INFO: Got PAC data of length %d\n",
          LogTime(), PROGRAM, (int)ad_data->length);

    /* Skip 16 bytes icommon RPC header
     * Skip 4 bytes RPC unique pointer referent
     * http://msdn.microsoft.com/en-gb/library/cc237933.aspx
     */
    /* Some data are pointers to data which follows the main KRB5 LOGON structure =>
     *         So need to read the data
     * some logical consistency checks are done when analysineg the pointer data
     */
    bpos = 20;
    /* 8 bytes LogonTime
     * 8 bytes LogoffTime
     * 8 bytes KickOffTime
     * 8 bytes PasswordLastSet
     * 8 bytes PasswordCanChange
     * 8 bytes PasswordMustChange
     */
    bpos = bpos+48;
    getustr(&EffectiveName);
    getustr(&FullName);
    getustr(&LogonScript);
    getustr(&ProfilePath);
    getustr(&HomeDirectory);
    getustr(&HomeDirectoryDrive);
    /* 2 bytes LogonCount
     * 2 bytes BadPasswordCount
     * 4 bytes UserID
     * 4 bytes PrimaryGroupId
     */
    bpos = bpos+12;
    GroupCount = get4byt();
    GroupIds = get4byt();
    /* 4 bytes UserFlags
     * 16 bytes UserSessionKey
     */
    bpos = bpos+20;
    getustr(&LogonServer);
    getustr(&LogonDomainName);
    LogonDomainId = get4byt();
    /* 8 bytes Reserved1
     * 4 bytes UserAccountControl
     * 4 bytes SubAuthStatus
     * 8 bytes LastSuccessfullLogon
     * 8 bytes LastFailedLogon
     * 4 bytes FailedLogonCount
     * 4 bytes Reserved2
     */
    bpos = bpos+40;
    SidCount = get4byt();
    ExtraSids = get4byt();
    /* 4 bytes ResourceGroupDomainSid
     * 4 bytes ResourceGroupCount
     * 4 bytes ResourceGroupIds
     */
    bpos = bpos+12;
    /*
     * Read all data from structure => Now check pointers
     */
    if (checkustr(&EffectiveName)<0)
        goto k5clean;
    if (checkustr(&FullName)<0)
        goto k5clean;
    if (checkustr(&LogonScript)<0)
        goto k5clean;
    if (checkustr(&ProfilePath)<0)
        goto k5clean;
    if (checkustr(&HomeDirectory)<0)
        goto k5clean;
    if (checkustr(&HomeDirectoryDrive)<0)
        goto k5clean;
    Rids = getgids(Rids,GroupIds,GroupCount);
    if (checkustr(&LogonServer)<0)
        goto k5clean;
    if (checkustr(&LogonDomainName)<0)
        goto k5clean;
    ad_groups = getdomaingids(ad_groups,LogonDomainId,Rids,GroupCount);
    if ((ad_groups = getextrasids(ad_groups,ExtraSids,SidCount))==NULL)
        goto k5clean;

    debug((char *) "%s| %s: INFO: Read %d of %d bytes \n", LogTime(), PROGRAM, bpos, (int)ad_data->length);
    if (Rids) {
        for ( l=0; l<(int)GroupCount; l++) {
            xfree(Rids[l]);
        }
        xfree(Rids);
    }
    krb5_free_data(context, ad_data);
    return ad_groups;
k5clean:
    if (Rids) {
        for ( l=0; l<(int)GroupCount; l++) {
            xfree(Rids[l]);
        }
        xfree(Rids);
    }
    krb5_free_data(context, ad_data);
    return NULL;
}
#endif

