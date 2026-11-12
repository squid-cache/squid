/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */

#include "squid.h"
#include "base/Assure.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "rfc1738.h"

#include "negotiate_kerberos.h"

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#if HAVE_GSSAPI && HAVE_KRB5_PAC_SUPPORT

#define LOGON_EXTRA_SIDS 0x0020
#define LOGON_RESOURCE_GROUPS 0x0200

/// A safety wrapper for legacy `p[bpos]` calls that lack buffer length checks.
/// Unlike the KrbBuffer class, this class does not own the memory it points to.
/// TODO: Callers should be refactored to use a BinaryTokenizer instead.
class KrbBufferPointer
{
public:
    using Storage = const unsigned char *;
    KrbBufferPointer(const Storage start, const size_t length): start_(start), length_(length) {}

    // the index is `int` because `bpos` is int
    const unsigned char &operator [](const int pos) const {
        Assure(pos >= 0);
        if (static_cast<unsigned int>(pos) >= length_)
            throw TextException("truncated input", Here());
        return start_[pos];
    }

private:
    Storage start_;
    size_t length_;
};

/// A safety wrapper for legacy pa=xcalloc()/pa[l]/xfree(pa) and similar calls
/// that leak memory when an exception is thrown and lack buffer length checks.
template <class T>
class KrbBuffer {
public:
    static_assert(std::is_trivial_v<T>, "xcalloc()/xfree() lifetime management is appropriate for T");
    static_assert(alignof(T) <= alignof(std::max_align_t), "xcalloc()-provided alignment is sufficient for T");

    explicit KrbBuffer(const size_t size):
        storage_(static_cast<T*>(xcalloc(sizeof(T), size))),
        size_(size) {}

    ~KrbBuffer() { xfree(storage_); }

    KrbBuffer(const KrbBuffer&) = delete;
    KrbBuffer& operator=(const KrbBuffer&) = delete;

    KrbBuffer(KrbBuffer &&other): storage_(std::exchange(other.storage_, nullptr)), size_(std::exchange(other.size_, 0)) {}
    KrbBuffer &operator=(KrbBuffer &&other) {
        if (this != &other) {
            xfree(storage_);
            storage_ = std::exchange(other.storage_, nullptr);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    operator T*() const {
        return storage_;
    }

    T &operator[](const size_t index) {
        // Normally, this would be an Assure() call, but this wrapper class
        // exists to help with dangerously written input parsing code where
        // out-of-bounds reads are a lot more likely to indicate invalid input.
        // TODO: Callers should be refactored to use a BinaryTokenizer instead.
        if (index >= size_)
            throw TextException("malformed encoding", Here());

        return storage_[index];
    }

    T &operator[](const int index) {
        Assure(index >= 0);
        return operator[](static_cast<size_t>(index));
    }

    T* get() { return storage_; }
    size_t size() const { return size_; }

private:
    /// Never-null storage containing size_ zero-initialized trivial objects.
    T* storage_;

    /// The number of objects stored in storage_
    size_t size_;
};

using KrbRids = std::vector< KrbBuffer<char> >;

/// Prevents double-xfree in legacy code converted to use KrbBuffer.
template <class T>
static void
xfree(const KrbBuffer<T> &) = delete;

static int bpos;

// XXX: This global conflicts with function parameters named `p`, preventing
// this file from including headers like sbuf/Stream.h. TODO: Migrate this (and
// other similar variables) and the functions using them inside a new C++ class.
static KrbBufferPointer p(nullptr, 0);

extern int
check_k5_err(krb5_context context, const char *function, krb5_error_code code);

void
align(int n)
{
    if (const auto r = bpos % n)
        bpos += (n - r);
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

static char *
pstrcpy( char *src, const char *dst)
{
    if (dst) {
        if (strlen(dst)>MAX_PAC_GROUP_SIZE)
            return nullptr;
        else
            return strcpy(src,dst);
    } else
        return src;
}

static char *
pstrcat( char *src, const char *dst)
{
    if (dst) {
        if (strlen(src)+strlen(dst)+1>MAX_PAC_GROUP_SIZE)
            return nullptr;
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

static KrbRids
getgids(const uint32_t GroupIds, const uint32_t GroupCount)
{
    if (GroupIds!= 0) {
        uint32_t ngroup;
        int l;

        align(4);
        ngroup = get4byt();
        if ( ngroup != GroupCount) {
            debug((char *) "%s| %s: ERROR: Group encoding error => GroupCount: %d Array size: %d\n",
                  LogTime(), PROGRAM, GroupCount, ngroup);
            // TODO: Move the above info into the exception text below after `p` global is gone.
            throw TextException("Cannot compute the RIDS list: Inconsistent group encoding", Here());
        }
        debug((char *) "%s| %s: INFO: Found %d rids\n", LogTime(), PROGRAM, GroupCount);

        KrbRids Rids;
        Rids.reserve(GroupCount);
        for ( l=0; l<(int)GroupCount; l++) {
            uint32_t sauth;
            Rids.emplace_back(4);
            memcpy((void *)Rids[l],(void *)&p[bpos],4);
            sauth = get4byt();
            debug((char *) "%s| %s: Info: Got rid: %u\n", LogTime(), PROGRAM, sauth);
            /* attribute */
            bpos = bpos+4;
        }
        return Rids;
    }
    throw TextException("Cannot compute the RIDS list: zero group IDs", Here());
}

static char *
getdomaingids(char *ad_groups, uint32_t DomainLogonId, KrbRids &Rids, uint32_t GroupCount)
{
    if (!ad_groups) {
        debug((char *) "%s| %s: ERR: No space to store groups\n",
              LogTime(), PROGRAM);
        return nullptr;
    }

    Assure(Rids.size() == GroupCount);

    if (DomainLogonId!= 0) {
        uint8_t rev;
        uint64_t idauth;
        char dli[256];
        int l;

        align(4);

        uint32_t nauth = get4byt();

        // check if nauth math will produce invalid length values on 32-bit
        static uint32_t maxGidCount = (UINT32_MAX-1-1-6)/4;
        if (nauth > maxGidCount) {
            debug((char *) "%s| %s: ERROR: Too many groups ! count > %d : %s\n",
                  LogTime(), PROGRAM, maxGidCount, ad_groups);
            return nullptr;
        }
        size_t length = 1+1+6+nauth*4;

        /* prepend rids with DomainID */
        for (l=0; l<(int)GroupCount; l++) {
            KrbBuffer<char> ag(length+4);
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
            size_t blen = base64_encode_update(&ctx, b64buf, length+4, reinterpret_cast<uint8_t*>(ag.get()));
            blen += base64_encode_final(&ctx, b64buf+blen);
            b64buf[expectedSz-1] = '\0';
            if (!pstrcat(ad_groups, b64buf)) {
                debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                      LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
            }
            xfree(b64buf);
        }

        /* mainly for debug only */
        rev = get1byt();
        bpos = bpos + 1; /*nsub*/
        idauth = get6byt_be();

        snprintf(dli,sizeof(dli),"S-%d-%lu",rev,(long unsigned int)idauth);
        for ( l=0; l<(int)nauth; l++ ) {
            uint32_t sauth;
            sauth = get4byt();
            // TODO: Encapsulate these loops and use ToSBuf() after `p` global is gone.
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
        int l;

        align(4);
        ngroup = get4byt();
        if ( ngroup != SidCount) {
            debug((char *) "%s| %s: ERROR: Group encoding error => SidCount: %d Array size: %d\n",
                  LogTime(), PROGRAM, SidCount, ngroup);
            return nullptr;
        }
        debug((char *) "%s| %s: INFO: Found %d ExtraSIDs\n", LogTime(), PROGRAM, SidCount);

        KrbBuffer<uint32_t> pa(SidCount);
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
                    return nullptr;
                }

                size_t length = 1+1+6+nauth*4;
                KrbBuffer<char> ag(length);
                memcpy((void *)ag,(const void*)&p[bpos],length);
                if (!ad_groups) {
                    debug((char *) "%s| %s: ERR: No space to store groups\n",
                          LogTime(), PROGRAM);
                    return nullptr;
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
                size_t blen = base64_encode_update(&ctx, b64buf, length, reinterpret_cast<uint8_t*>(ag.get()));
                blen += base64_encode_final(&ctx, b64buf+blen);
                b64buf[expectedSz-1] = '\0';
                if (!pstrcat(ad_groups, reinterpret_cast<char*>(b64buf))) {
                    debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                          LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
                }
                xfree(b64buf);

                rev = get1byt();
                bpos = bpos + 1; /* nsub */
                idauth = get6byt_be();

                snprintf(es,sizeof(es),"S-%d-%lu",rev,(long unsigned int)idauth);
                for (int k=0; k<(int)nauth; k++ ) {
                    uint32_t sauth;
                    sauth = get4byt();
                    // TODO: Encapsulate these loops and use ToSBuf() after `p` global is gone.
                    snprintf((char *)&es[strlen(es)],sizeof(es)-strlen(es),"-%u",sauth);
                }
                debug((char *) "%s| %s: INFO: Got ExtraSid %s\n", LogTime(), PROGRAM, es);
            }
        }
    }
    return ad_groups;
}

static char *
get_resource_group_domain_sid(const uint32_t ResourceGroupDomainSid, size_t &length)
{
    if (ResourceGroupDomainSid != 0) {
        uint8_t rev;
        uint64_t idauth;
        char dli[256];

        align(4);

        // ResourceGroupDomainSid structure:
        //  4 bytes nauth
        //  1 byte revision  = 1
        //  1 byte nsub (it is equal to the number of dashes minus two)
        //  6 bytes idauth   (for NT Authority it is 5)
        //  4 bytes sauth1
        //  ... nauth timss
        //  4 bytes sauthN

        uint32_t nauth = get4byt();

        // check if nauth math will produce invalid length values on 32-bit
        static uint32_t maxGidCount = (UINT32_MAX - 4 - 1 - 1 - 6)/4;
        if (nauth > maxGidCount) {
            debug((char *) "%s| %s: ERROR: Too many subAuths in the ResourceGroupDomainSID: nauth = %d > %d\n",
                  LogTime(), PROGRAM, nauth, maxGidCount);
            return nullptr;
        }

        // length = revision[1byte]+nsub[1byte]+idauth[6bytes]+nauth*sauth[4bytes]
        length = 1 + 1 + 6 + nauth*4;

        KrbBuffer<char> sid(length);
        // 1 byte revision
        // 1 byte nsub
        // 6 bytes+nauth*4bytes idauth+sauths
        memcpy((void *)&sid[0], (const void*)&p[bpos], 1);
        memcpy((void *)&sid[1], (const void*)&p[bpos+1], 1);
        sid[1]++;  // ++ as it will be used in a rid concatenation
        memcpy((void *)&sid[2], (const void*)&p[bpos+2], 6 + nauth*4);

        /* mainly for debug only */
        rev = get1byt();
        bpos = bpos + 1; /* nsub */
        idauth = get6byt_be();

        int rv = snprintf(dli, sizeof(dli), "S-%d-%lu", rev, (long unsigned int)idauth);
        assert(rv > 0);
        for (int l=0; l<(int)nauth; l++) {
            uint32_t sauth;
            sauth = get4byt();
            // TODO: Encapsulate these loops and use ToSBuf() after `p` global is gone.
            rv = snprintf((char *)&dli[strlen(dli)], sizeof(dli) - strlen(dli), "-%u", sauth);
        }
        debug((char *) "%s| %s: INFO: Got ResourceGroupDomainSid %s\n", LogTime(), PROGRAM, dli);
        return sid;
    }

    length = 0;
    return nullptr;
}

static bool
get_resource_groups(char *ad_groups, uint32_t ResourceGroupDomainSid,  uint32_t ResourceGroupIds, uint32_t ResourceGroupCount)
{
    if (!ad_groups) {
        debug((char *) "%s| %s: ERR: No space to store resource groups\n",
              LogTime(), PROGRAM);
        return false;
    }

    size_t group_domain_sid_len = 0;
    const auto resource_group_domain_sid = get_resource_group_domain_sid(ResourceGroupDomainSid, group_domain_sid_len);
    if (!resource_group_domain_sid)
        return false;

    if (ResourceGroupIds != 0) {
        align(4);
        uint32_t ngroup = get4byt();
        if (ngroup != ResourceGroupCount) {
            debug((char *) "%s| %s: ERROR: Group encoding error => ResourceGroupCount: %d != Array size: %d\n",
                  LogTime(), PROGRAM, ResourceGroupCount, ngroup);
            xfree(resource_group_domain_sid);
            return false;
        }
        debug((char *) "%s| %s: INFO: Found %d Resource Group rids\n", LogTime(), PROGRAM, ResourceGroupCount);

        // prepare a group template which begins with the resource_group_domain_sid
        size_t length = group_domain_sid_len + 4;  // +4 for a rid concatenation
        KrbBuffer<char> st(length);

        memcpy((void *)st, (const void*)resource_group_domain_sid, group_domain_sid_len); // template

        for (int l=0; l < (int)ResourceGroupCount; l++) {
            uint32_t sauth;
            memcpy((void *)&st[group_domain_sid_len], (const void*)&p[bpos], 4);  // rid concatenation

            if (!pstrcat(ad_groups, " group=")) {
                debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                      LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
            }

            struct base64_encode_ctx ctx;
            base64_encode_init(&ctx);
            const uint32_t expectedSz = base64_encode_len(length) + 1 /* terminator */;
            char *b64buf = static_cast<char *>(xcalloc(expectedSz, 1));
            size_t blen = base64_encode_update(&ctx, b64buf, length, reinterpret_cast<uint8_t*>(st.get()));
            blen += base64_encode_final(&ctx, b64buf + blen);
            b64buf[expectedSz - 1] = '\0';
            if (!pstrcat(ad_groups, reinterpret_cast<char*>(b64buf))) {
                debug((char *) "%s| %s: WARN: Too many groups ! size > %d : %s\n",
                      LogTime(), PROGRAM, MAX_PAC_GROUP_SIZE, ad_groups);
            }
            xfree(b64buf);

            sauth = get4byt();
            debug((char *) "%s| %s: Info: Got rid: %u\n", LogTime(), PROGRAM, sauth);
            /* attribute */
            bpos = bpos + 4;
        }
    }

    xfree(resource_group_domain_sid);
    return true;
}

/// implements get_ad_groups() except for C++ exception handling
static char *
get_ad_groups_(char *ad_groups, krb5_context context, krb5_pac pac)
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
    uint32_t UserFlags=0;
    uint32_t ExtraSids=0;
    uint32_t ResourceGroupDomainSid=0;
    uint32_t ResourceGroupCount=0;
    uint32_t ResourceGroupIds=0;

    if (!ad_groups) {
        debug((char *) "%s| %s: ERR: No space to store groups\n",
              LogTime(), PROGRAM);
        return nullptr;
    }

    const auto ad_data_deleter = [context](krb5_data * const data) {
        if (data)
            krb5_free_data(context, data);
    };

    std::unique_ptr<krb5_data, decltype(ad_data_deleter)> ad_data(
        static_cast<krb5_data*>(xcalloc(1, sizeof(krb5_data))),
        ad_data_deleter);

#define KERB_LOGON_INFO 1
    ret = krb5_pac_get_buffer(context, pac, KERB_LOGON_INFO, ad_data.get());
    if (check_k5_err(context, "krb5_pac_get_buffer", ret))
        return nullptr;

    p = KrbBufferPointer(reinterpret_cast<unsigned char *>(ad_data->data), ad_data->length);

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
    UserFlags = get4byt();
    /// 16 bytes UserSessionKey
    bpos = bpos+16;
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

    ResourceGroupDomainSid = get4byt();
    ResourceGroupCount = get4byt();
    ResourceGroupIds = get4byt();

    /*
     * Read all data from structure => Now check pointers
     */
    if (checkustr(&EffectiveName)<0)
        return nullptr;
    if (checkustr(&FullName)<0)
        return nullptr;
    if (checkustr(&LogonScript)<0)
        return nullptr;
    if (checkustr(&ProfilePath)<0)
        return nullptr;
    if (checkustr(&HomeDirectory)<0)
        return nullptr;
    if (checkustr(&HomeDirectoryDrive)<0)
        return nullptr;
    auto Rids = getgids(GroupIds,GroupCount);
    if (checkustr(&LogonServer)<0)
        return nullptr;
    if (checkustr(&LogonDomainName)<0)
        return nullptr;
    ad_groups = getdomaingids(ad_groups,LogonDomainId,Rids,GroupCount);

    // https://learn.microsoft.com/en-us/previous-versions/aa302203(v=msdn.10)?redirectedfrom=MSDN#top-level-pac-structure
    if ((UserFlags&LOGON_EXTRA_SIDS) != 0) {
        // EXTRA_SIDS structures are present and valid
        debug((char *) "%s| %s: Info: EXTRA_SIDS are present\n", LogTime(), PROGRAM);
        if ((ad_groups = getextrasids(ad_groups,ExtraSids,SidCount)) == nullptr)
            return nullptr;
    }

    if ((UserFlags&LOGON_RESOURCE_GROUPS) != 0 && ResourceGroupDomainSid && ResourceGroupIds && ResourceGroupCount) {
        // RESOURCE_GROUPS structures are present and valid
        debug((char *) "%s| %s: Info: RESOURCE_GROUPS are present\n", LogTime(), PROGRAM);
        if (!get_resource_groups(ad_groups, ResourceGroupDomainSid, ResourceGroupIds, ResourceGroupCount))
            return nullptr;
    }

    debug((char *) "%s| %s: INFO: Read %d of %d bytes \n", LogTime(), PROGRAM, bpos, (int)ad_data->length);
    return ad_groups;
}

char *
get_ad_groups(char * const ad_groups, const krb5_context context, const krb5_pac pac)
{
    try {
        return get_ad_groups_(ad_groups, context, pac);
    }
    catch (...) {
        debugs(29, DBG_CRITICAL, "ERROR: Failed to parse AD groups in a Kerberos service response" <<
               Debug::Extra << "exception: " << CurrentException);
        return nullptr;
    }
}

#endif /* HAVE_GSSAPI && HAVE_KRB5_PAC_SUPPORT */
