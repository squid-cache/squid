/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * ext_ad_group_acl: lookup group membership in a Windows
 * Active Directory domain
 *
 * (C)2008-2009 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * Based on mswin_check_lm_group by Guido Serassio.
 *
 * Dependencies: Windows 2000 SP4 and later.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * History:
 *
 * Version 2.1
 * 20-09-2009 Guido Serassio
 *              Added explicit Global Catalog query
 *
 * Version 2.0
 * 20-07-2009 Guido Serassio
 *              Global groups support rewritten, now is based on ADSI.
 *              New Features:
 *              - support for Domain Local, Domain Global ad Universal
 *                groups
 *              - full group nesting support
 * Version 1.0
 * 02-05-2008 Guido Serassio
 *              First release, based on mswin_check_lm_group.
 *
 * This is a helper for the external ACL interface for Squid Cache
 *
 * It reads from the standard input the domain username and a list of
 * groups and tries to match it against the groups membership of the
 * specified username.
 *
 * Returns `OK' if the user belongs to a group or `ERR' otherwise, as
 * described on http://devel.squid-cache.org/external_acl/config.html
 *
 */

#include "squid.h"
#include "helper/protocol_defines.h"
#include "include/util.h"

#if _SQUID_CYGWIN_
#include <wchar.h>
int _wcsicmp(const wchar_t *, const wchar_t *);
#endif

#undef assert
#include <cassert>
#include <cctype>
#include <cstring>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <windows.h>
#include <objbase.h>
#include <initguid.h>
#include <adsiid.h>
#include <iads.h>
#include <adshlp.h>
#include <adserr.h>
#include <lm.h>
#include <dsrole.h>
#include <sddl.h>

enum ADSI_PATH {
    LDAP_MODE,
    GC_MODE
} ADSI_Path;

int use_global = 0;
char *program_name;
pid_t mypid;
char *machinedomain;
int use_case_insensitive_compare = 0;
char *DefaultDomain = nullptr;
const char NTV_VALID_DOMAIN_SEPARATOR[] = "\\/";
int numberofgroups = 0;
int WIN32_COM_initialized = 0;
char *WIN32_ErrorMessage = nullptr;
wchar_t **User_Groups;
int User_Groups_Count = 0;

wchar_t *My_NameTranslate(wchar_t *, int, int);
char *Get_WIN32_ErrorMessage(HRESULT);

void
CloseCOM(void)
{
    if (WIN32_COM_initialized == 1)
        CoUninitialize();
}

HRESULT
GetLPBYTEtoOctetString(VARIANT * pVar, LPBYTE * ppByte)
{
    HRESULT hr = E_FAIL;
    void HUGEP *pArray;
    long lLBound, lUBound, cElements;

    if ((!pVar) || (!ppByte))
        return E_INVALIDARG;
    if ((pVar->n1.n2.vt) != (VT_UI1 | VT_ARRAY))
        return E_INVALIDARG;

    hr = SafeArrayGetLBound(V_ARRAY(pVar), 1, &lLBound);
    hr = SafeArrayGetUBound(V_ARRAY(pVar), 1, &lUBound);

    cElements = lUBound - lLBound + 1;
    hr = SafeArrayAccessData(V_ARRAY(pVar), &pArray);
    if (SUCCEEDED(hr)) {
        LPBYTE pTemp = (LPBYTE) pArray;
        *ppByte = (LPBYTE) CoTaskMemAlloc(cElements);
        if (*ppByte)
            memcpy(*ppByte, pTemp, cElements);
        else
            hr = E_OUTOFMEMORY;
    }
    SafeArrayUnaccessData(V_ARRAY(pVar));

    return hr;
}

wchar_t *
Get_primaryGroup(IADs * pUser)
{
    HRESULT hr;
    VARIANT var;
    unsigned User_primaryGroupID;
    char tmpSID[SECURITY_MAX_SID_SIZE * 2];
    wchar_t *wc = nullptr, *result = nullptr;
    int wcsize;

    VariantInit(&var);

    /* Get the primaryGroupID property */
    hr = pUser->lpVtbl->Get(pUser, L"primaryGroupID", &var);
    if (SUCCEEDED(hr)) {
        User_primaryGroupID = var.n1.n2.n3.uintVal;
    } else {
        debug("Get_primaryGroup: cannot get primaryGroupID, ERROR: %s\n", Get_WIN32_ErrorMessage(hr));
        VariantClear(&var);
        return result;
    }
    VariantClear(&var);

    /*Get the objectSid property */
    hr = pUser->lpVtbl->Get(pUser, L"objectSid", &var);
    if (SUCCEEDED(hr)) {
        PSID pObjectSID;
        LPBYTE pByte = nullptr;
        char *szSID = nullptr;
        hr = GetLPBYTEtoOctetString(&var, &pByte);

        pObjectSID = (PSID) pByte;

        /* Convert SID to string. */
        ConvertSidToStringSid(pObjectSID, &szSID);
        CoTaskMemFree(pByte);

        *(strrchr(szSID, '-') + 1) = '\0';
        snprintf(tmpSID, sizeof(tmpSID)-1, "%s%u", szSID, User_primaryGroupID);

        wcsize = MultiByteToWideChar(CP_ACP, 0, tmpSID, -1, wc, 0);
        wc = (wchar_t *) xmalloc(wcsize * sizeof(wchar_t));
        MultiByteToWideChar(CP_ACP, 0, tmpSID, -1, wc, wcsize);
        LocalFree(szSID);

        result = My_NameTranslate(wc, ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME, ADS_NAME_TYPE_1779);
        safe_free(wc);

        if (result == NULL)
            debug("Get_primaryGroup: cannot get DN for %s.\n", tmpSID);
        else
            debug("Get_primaryGroup: Primary group DN: %S.\n", result);
    } else
        debug("Get_primaryGroup: cannot get objectSid, ERROR: %s\n", Get_WIN32_ErrorMessage(hr));
    VariantClear(&var);
    return result;
}

char *
Get_WIN32_ErrorMessage(HRESULT hr)
{
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  nullptr,
                  hr,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) & WIN32_ErrorMessage,
                  0,
                  nullptr);
    return WIN32_ErrorMessage;
}

wchar_t *
My_NameTranslate(wchar_t * name, int in_format, int out_format)
{
    IADsNameTranslate *pNto;
    HRESULT hr;
    BSTR bstr;
    wchar_t *wc;

    if (WIN32_COM_initialized == 0) {
        hr = CoInitialize(NULL);
        if (FAILED(hr)) {
            debug("My_NameTranslate: cannot initialize COM interface, ERROR: %s\n", Get_WIN32_ErrorMessage(hr));
            /* This is a fatal error */
            exit(EXIT_FAILURE);
        }
        WIN32_COM_initialized = 1;
    }
    hr = CoCreateInstance(&CLSID_NameTranslate,
                          nullptr,
                          CLSCTX_INPROC_SERVER,
                          &IID_IADsNameTranslate,
                          (void **) &pNto);
    if (FAILED(hr)) {
        debug("My_NameTranslate: cannot create COM instance, ERROR: %s\n", Get_WIN32_ErrorMessage(hr));
        /* This is a fatal error */
        exit(EXIT_FAILURE);
    }
    hr = pNto->lpVtbl->Init(pNto, ADS_NAME_INITTYPE_GC, L"");
    if (FAILED(hr)) {
        debug("My_NameTranslate: cannot initialise NameTranslate API, ERROR: %s\n", Get_WIN32_ErrorMessage(hr));
        pNto->lpVtbl->Release(pNto);
        /* This is a fatal error */
        exit(EXIT_FAILURE);
    }
    hr = pNto->lpVtbl->Set(pNto, in_format, name);
    if (FAILED(hr)) {
        debug("My_NameTranslate: cannot set translate of %S, ERROR: %s\n", name, Get_WIN32_ErrorMessage(hr));
        pNto->lpVtbl->Release(pNto);
        return nullptr;
    }
    hr = pNto->lpVtbl->Get(pNto, out_format, &bstr);
    if (FAILED(hr)) {
        debug("My_NameTranslate: cannot get translate of %S, ERROR: %s\n", name, Get_WIN32_ErrorMessage(hr));
        pNto->lpVtbl->Release(pNto);
        return nullptr;
    }
    debug("My_NameTranslate: %S translated to %S\n", name, bstr);

    wc = (wchar_t *) xmalloc((wcslen(bstr) + 1) * sizeof(wchar_t));
    wcscpy(wc, bstr);
    SysFreeString(bstr);
    pNto->lpVtbl->Release(pNto);
    return wc;
}

wchar_t *
GetLDAPPath(wchar_t * Base_DN, int query_mode)
{
    wchar_t *wc;

    wc = (wchar_t *) xmalloc((wcslen(Base_DN) + 8) * sizeof(wchar_t));

    if (query_mode == LDAP_MODE)
        wcscpy(wc, L"LDAP://");
    else
        wcscpy(wc, L"GC://");
    wcscat(wc, Base_DN);

    return wc;
}

char *
GetDomainName(void)
{
    static char *DomainName = nullptr;
    PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDSRoleInfo;
    DWORD netret;

    if ((netret = DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, (PBYTE *) & pDSRoleInfo) == ERROR_SUCCESS)) {
        /*
         * Check the machine role.
         */

        if ((pDSRoleInfo->MachineRole == DsRole_RoleMemberWorkstation) ||
                (pDSRoleInfo->MachineRole == DsRole_RoleMemberServer) ||
                (pDSRoleInfo->MachineRole == DsRole_RoleBackupDomainController) ||
                (pDSRoleInfo->MachineRole == DsRole_RolePrimaryDomainController)) {

            size_t len = wcslen(pDSRoleInfo->DomainNameFlat);

            /* allocate buffer for str + null termination */
            safe_free(DomainName);
            DomainName = (char *) xmalloc(len + 1);

            /* copy unicode buffer */
            WideCharToMultiByte(CP_ACP, 0, pDSRoleInfo->DomainNameFlat, -1, DomainName, len, nullptr, nullptr);

            /* add null termination */
            DomainName[len] = '\0';

            /*
             * Member of a domain. Display it in debug mode.
             */
            debug("Member of Domain %s\n", DomainName);
            debug("Into forest %S\n", pDSRoleInfo->DomainForestName);

        } else {
            debug("Not a Domain member\n");
        }
    } else
        debug("GetDomainName: ERROR DsRoleGetPrimaryDomainInformation returned: %s\n", Get_WIN32_ErrorMessage(netret));

    /*
     * Free the allocated memory.
     */
    if (pDSRoleInfo != NULL)
        DsRoleFreeMemory(pDSRoleInfo);

    return DomainName;
}

int
add_User_Group(wchar_t * Group)
{
    wchar_t **array;

    if (User_Groups_Count == 0) {
        User_Groups = (wchar_t **) xmalloc(sizeof(wchar_t *));
        *User_Groups = nullptr;
        ++User_Groups_Count;
    }
    array = User_Groups;
    while (*array) {
        if (wcscmp(Group, *array) == 0)
            return 0;
        ++array;
    }
    User_Groups = (wchar_t **) xrealloc(User_Groups, sizeof(wchar_t *) * (User_Groups_Count + 1));
    User_Groups[User_Groups_Count] = nullptr;
    User_Groups[User_Groups_Count - 1] = (wchar_t *) xmalloc((wcslen(Group) + 1) * sizeof(wchar_t));
    wcscpy(User_Groups[User_Groups_Count - 1], Group);
    ++User_Groups_Count;

    return 1;
}

/* returns 0 on match, -1 if no match */
static int
wccmparray(const wchar_t * str, const wchar_t ** array)
{
    while (*array) {
        debug("Windows group: %S, Squid group: %S\n", str, *array);
        if (wcscmp(str, *array) == 0)
            return 0;
        ++array;
    }
    return -1;
}

/* returns 0 on match, -1 if no match */
static int
wcstrcmparray(const wchar_t * str, const char **array)
{
    WCHAR wszGroup[GNLEN + 1];  // Unicode Group

    while (*array) {
        MultiByteToWideChar(CP_ACP, 0, *array,
                            strlen(*array) + 1, wszGroup, sizeof(wszGroup) / sizeof(wszGroup[0]));
        debug("Windows group: %S, Squid group: %S\n", str, wszGroup);
        if ((use_case_insensitive_compare ? _wcsicmp(str, wszGroup) : wcscmp(str, wszGroup)) == 0)
            return 0;
        ++array;
    }
    return -1;
}

HRESULT
Recursive_Memberof(IADs * pObj)
{
    VARIANT var;
    long lBound, uBound;
    HRESULT hr;

    VariantInit(&var);
    hr = pObj->lpVtbl->Get(pObj, L"memberOf", &var);
    if (SUCCEEDED(hr)) {
        if (VT_BSTR == var.n1.n2.vt) {
            if (add_User_Group(var.n1.n2.n3.bstrVal)) {
                wchar_t *Group_Path;
                IADs *pGrp;

                Group_Path = GetLDAPPath(var.n1.n2.n3.bstrVal, GC_MODE);
                hr = ADsGetObject(Group_Path, &IID_IADs, (void **) &pGrp);
                if (SUCCEEDED(hr)) {
                    hr = Recursive_Memberof(pGrp);
                    pGrp->lpVtbl->Release(pGrp);
                    safe_free(Group_Path);
                    Group_Path = GetLDAPPath(var.n1.n2.n3.bstrVal, LDAP_MODE);
                    hr = ADsGetObject(Group_Path, &IID_IADs, (void **) &pGrp);
                    if (SUCCEEDED(hr)) {
                        hr = Recursive_Memberof(pGrp);
                        pGrp->lpVtbl->Release(pGrp);
                    } else
                        debug("Recursive_Memberof: ERROR ADsGetObject for %S failed: %s\n", Group_Path, Get_WIN32_ErrorMessage(hr));
                } else
                    debug("Recursive_Memberof: ERROR ADsGetObject for %S failed: %s\n", Group_Path, Get_WIN32_ErrorMessage(hr));
                safe_free(Group_Path);
            }
        } else {
            if (SUCCEEDED(SafeArrayGetLBound(V_ARRAY(&var), 1, &lBound)) &&
                    SUCCEEDED(SafeArrayGetUBound(V_ARRAY(&var), 1, &uBound))) {
                VARIANT elem;
                while (lBound <= uBound) {
                    hr = SafeArrayGetElement(V_ARRAY(&var), &lBound, &elem);
                    if (SUCCEEDED(hr)) {
                        if (add_User_Group(elem.n1.n2.n3.bstrVal)) {
                            wchar_t *Group_Path;
                            IADs *pGrp;

                            Group_Path = GetLDAPPath(elem.n1.n2.n3.bstrVal, GC_MODE);
                            hr = ADsGetObject(Group_Path, &IID_IADs, (void **) &pGrp);
                            if (SUCCEEDED(hr)) {
                                hr = Recursive_Memberof(pGrp);
                                pGrp->lpVtbl->Release(pGrp);
                                safe_free(Group_Path);
                                Group_Path = GetLDAPPath(elem.n1.n2.n3.bstrVal, LDAP_MODE);
                                hr = ADsGetObject(Group_Path, &IID_IADs, (void **) &pGrp);
                                if (SUCCEEDED(hr)) {
                                    hr = Recursive_Memberof(pGrp);
                                    pGrp->lpVtbl->Release(pGrp);
                                    safe_free(Group_Path);
                                } else
                                    debug("Recursive_Memberof: ERROR ADsGetObject for %S failed: %s\n", Group_Path, Get_WIN32_ErrorMessage(hr));
                            } else
                                debug("Recursive_Memberof: ERROR ADsGetObject for %S failed: %s\n", Group_Path, Get_WIN32_ErrorMessage(hr));
                            safe_free(Group_Path);
                        }
                        VariantClear(&elem);
                    } else {
                        debug("Recursive_Memberof: ERROR SafeArrayGetElement failed: %s\n", Get_WIN32_ErrorMessage(hr));
                        VariantClear(&elem);
                    }
                    ++lBound;
                }
            } else
                debug("Recursive_Memberof: ERROR SafeArrayGetxBound failed: %s\n", Get_WIN32_ErrorMessage(hr));
        }
        VariantClear(&var);
    } else {
        if (hr != E_ADS_PROPERTY_NOT_FOUND)
            debug("Recursive_Memberof: ERROR getting memberof attribute: %s\n", Get_WIN32_ErrorMessage(hr));
    }
    return hr;
}

static wchar_t **
build_groups_DN_array(const char **array, char *userdomain)
{
    wchar_t *wc = nullptr;
    int wcsize;
    int source_group_format;
    char Group[GNLEN + 1];

    wchar_t **wc_array, **entry;

    entry = wc_array = (wchar_t **) xmalloc((numberofgroups + 1) * sizeof(wchar_t *));

    while (*array) {
        if (strchr(*array, '/') != NULL) {
            strncpy(Group, *array, GNLEN);
            source_group_format = ADS_NAME_TYPE_CANONICAL;
        } else {
            source_group_format = ADS_NAME_TYPE_NT4;
            if (strchr(*array, '\\') == NULL) {
                strcpy(Group, userdomain);
                strcat(Group, "\\");
                strncat(Group, *array, GNLEN - sizeof(userdomain) - 1);
            } else
                strncpy(Group, *array, GNLEN);
        }

        wcsize = MultiByteToWideChar(CP_ACP, 0, Group, -1, wc, 0);
        wc = (wchar_t *) xmalloc(wcsize * sizeof(wchar_t));
        MultiByteToWideChar(CP_ACP, 0, Group, -1, wc, wcsize);
        *entry = My_NameTranslate(wc, source_group_format, ADS_NAME_TYPE_1779);
        safe_free(wc);
        ++array;
        if (*entry == NULL) {
            debug("build_groups_DN_array: cannot get DN for '%s'.\n", Group);
            continue;
        }
        ++entry;
    }
    *entry = nullptr;
    return wc_array;
}

/* returns 1 on success, 0 on failure */
int
Valid_Local_Groups(char *UserName, const char **Groups)
{
    int result = 0;
    char *Domain_Separator;
    WCHAR wszUserName[UNLEN + 1];   /* Unicode user name */

    LPLOCALGROUP_USERS_INFO_0 pBuf;
    LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = -1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD i;
    DWORD dwTotalCount = 0;
    LPBYTE pBufTmp = nullptr;

    if ((Domain_Separator = strchr(UserName, '/')) != NULL)
        *Domain_Separator = '\\';

    debug("Valid_Local_Groups: checking group membership of '%s'.\n", UserName);

    /* Convert ANSI User Name and Group to Unicode */

    MultiByteToWideChar(CP_ACP, 0, UserName,
                        strlen(UserName) + 1, wszUserName, sizeof(wszUserName) / sizeof(wszUserName[0]));

    /*
     * Call the NetUserGetLocalGroups function
     * specifying information level 0.
     *
     * The LG_INCLUDE_INDIRECT flag specifies that the
     * function should also return the names of the local
     * groups in which the user is indirectly a member.
     */
    nStatus = NetUserGetLocalGroups(nullptr,
                                    wszUserName,
                                    dwLevel,
                                    dwFlags,
                                    &pBufTmp,
                                    dwPrefMaxLen,
                                    &dwEntriesRead,
                                    &dwTotalEntries);
    pBuf = (LPLOCALGROUP_USERS_INFO_0) pBufTmp;
    /*
     * If the call succeeds,
     */
    if (nStatus == NERR_Success) {
        if ((pTmpBuf = pBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; ++i) {
                assert(pTmpBuf != NULL);
                if (pTmpBuf == NULL) {
                    result = 0;
                    break;
                }
                if (wcstrcmparray(pTmpBuf->lgrui0_name, Groups) == 0) {
                    result = 1;
                    break;
                }
                ++pTmpBuf;
                ++dwTotalCount;
            }
        }
    } else {
        debug("Valid_Local_Groups: ERROR NetUserGetLocalGroups returned: %s\n", Get_WIN32_ErrorMessage(nStatus));
        result = 0;
    }
    /*
     * Free the allocated memory.
     */
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    return result;
}

/* returns 1 on success, 0 on failure */
int
Valid_Global_Groups(char *UserName, const char **Groups)
{
    int result = 0;
    WCHAR wszUser[DNLEN + UNLEN + 2];   /* Unicode user name */
    char NTDomain[DNLEN + UNLEN + 2];

    char *domain_qualify = nullptr;
    char User[DNLEN + UNLEN + 2];
    size_t j;

    wchar_t *User_DN, *User_LDAP_path, *User_PrimaryGroup;
    wchar_t **wszGroups, **tmp;
    IADs *pUser;
    HRESULT hr;

    strncpy(NTDomain, UserName, sizeof(NTDomain));

    for (j = 0; j < strlen(NTV_VALID_DOMAIN_SEPARATOR); ++j) {
        if ((domain_qualify = strchr(NTDomain, NTV_VALID_DOMAIN_SEPARATOR[j])) != NULL)
            break;
    }
    if (domain_qualify == NULL) {
        strncpy(User, DefaultDomain, DNLEN);
        strcat(User, "\\");
        strncat(User, UserName, UNLEN);
        strncpy(NTDomain, DefaultDomain, DNLEN);
    } else {
        domain_qualify[0] = '\\';
        strncpy(User, NTDomain, DNLEN + UNLEN + 2);
        domain_qualify[0] = '\0';
    }

    debug("Valid_Global_Groups: checking group membership of '%s'.\n", User);

    /* Convert ANSI User Name to Unicode */

    MultiByteToWideChar(CP_ACP, 0, User,
                        strlen(User) + 1, wszUser,
                        sizeof(wszUser) / sizeof(wszUser[0]));

    /* Get CN of User */
    if ((User_DN = My_NameTranslate(wszUser, ADS_NAME_TYPE_NT4, ADS_NAME_TYPE_1779)) == NULL) {
        debug("Valid_Global_Groups: cannot get DN for '%s'.\n", User);
        return result;
    }
    wszGroups = build_groups_DN_array(Groups, NTDomain);

    User_LDAP_path = GetLDAPPath(User_DN, GC_MODE);

    hr = ADsGetObject(User_LDAP_path, &IID_IADs, (void **) &pUser);
    if (SUCCEEDED(hr)) {
        wchar_t *User_PrimaryGroup_Path;
        IADs *pGrp;

        User_PrimaryGroup = Get_primaryGroup(pUser);
        if (User_PrimaryGroup == NULL)
            debug("Valid_Global_Groups: cannot get Primary Group for '%s'.\n", User);
        else {
            add_User_Group(User_PrimaryGroup);
            User_PrimaryGroup_Path = GetLDAPPath(User_PrimaryGroup, GC_MODE);
            hr = ADsGetObject(User_PrimaryGroup_Path, &IID_IADs, (void **) &pGrp);
            if (SUCCEEDED(hr)) {
                hr = Recursive_Memberof(pGrp);
                pGrp->lpVtbl->Release(pGrp);
                safe_free(User_PrimaryGroup_Path);
                User_PrimaryGroup_Path = GetLDAPPath(User_PrimaryGroup, LDAP_MODE);
                hr = ADsGetObject(User_PrimaryGroup_Path, &IID_IADs, (void **) &pGrp);
                if (SUCCEEDED(hr)) {
                    hr = Recursive_Memberof(pGrp);
                    pGrp->lpVtbl->Release(pGrp);
                } else
                    debug("Valid_Global_Groups: ADsGetObject for %S failed, ERROR: %s\n", User_PrimaryGroup_Path, Get_WIN32_ErrorMessage(hr));
            } else
                debug("Valid_Global_Groups: ADsGetObject for %S failed, ERROR: %s\n", User_PrimaryGroup_Path, Get_WIN32_ErrorMessage(hr));
            safe_free(User_PrimaryGroup_Path);
        }
        hr = Recursive_Memberof(pUser);
        pUser->lpVtbl->Release(pUser);
        safe_free(User_LDAP_path);
        User_LDAP_path = GetLDAPPath(User_DN, LDAP_MODE);
        hr = ADsGetObject(User_LDAP_path, &IID_IADs, (void **) &pUser);
        if (SUCCEEDED(hr)) {
            hr = Recursive_Memberof(pUser);
            pUser->lpVtbl->Release(pUser);
        } else
            debug("Valid_Global_Groups: ADsGetObject for %S failed, ERROR: %s\n", User_LDAP_path, Get_WIN32_ErrorMessage(hr));

        tmp = User_Groups;
        while (*tmp) {
            if (wccmparray(*tmp, wszGroups) == 0) {
                result = 1;
                break;
            }
            ++tmp;
        }
    } else
        debug("Valid_Global_Groups: ADsGetObject for %S failed, ERROR: %s\n", User_LDAP_path, Get_WIN32_ErrorMessage(hr));

    safe_free(User_DN);
    safe_free(User_LDAP_path);
    safe_free(User_PrimaryGroup);
    tmp = wszGroups;
    while (*tmp) {
        safe_free(*tmp);
        ++tmp;
    }
    safe_free(wszGroups);

    tmp = User_Groups;
    while (*tmp) {
        safe_free(*tmp);
        ++tmp;
    }
    safe_free(User_Groups);
    User_Groups_Count = 0;

    return result;
}

static void
usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-D domain][-G][-c][-d][-h]\n"
            " -D    default user Domain\n"
            " -G    enable Active Directory Global group mode\n"
            " -c    use case insensitive compare (local mode only)\n"
            " -d    enable debugging\n"
            " -h    this message\n",
            program);
}

void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "D:Gcdh"))) {
        switch (opt) {
        case 'D':
            DefaultDomain = xstrndup(optarg, DNLEN + 1);
            strlwr(DefaultDomain);
            break;
        case 'G':
            use_global = 1;
            break;
        case 'c':
            use_case_insensitive_compare = 1;
            break;
        case 'd':
            debug_enabled = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        case '?':
            opt = optopt;
            [[fallthrough]];
        default:
            fprintf(stderr, "%s: FATAL: Unknown option: -%c. Exiting\n", program_name, opt);
            usage(argv[0]);
            exit(EXIT_FAILURE);
            break;      /* not reached */
        }
    }
}

int
main(int argc, char *argv[])
{
    char *p;
    char buf[HELPER_INPUT_BUFFER];
    char *username;
    char *group;
    const char *groups[512];
    int n;

    if (argc > 0) {     /* should always be true */
        program_name = strrchr(argv[0], '/');
        if (program_name == NULL)
            program_name = argv[0];
    } else {
        program_name = "(unknown)";
    }
    mypid = getpid();

    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);

    /* Check Command Line */
    process_options(argc, argv);

    if (use_global) {
        if ((machinedomain = GetDomainName()) == NULL) {
            fprintf(stderr, "%s: FATAL: Can't read machine domain\n", program_name);
            exit(EXIT_FAILURE);
        }
        strlwr(machinedomain);
        if (!DefaultDomain)
            DefaultDomain = xstrdup(machinedomain);
    }
    debug("%s " VERSION " " SQUID_BUILD_INFO " starting up...\n", argv[0]);
    if (use_global)
        debug("Domain Global group mode enabled using '%s' as default domain.\n", DefaultDomain);
    if (use_case_insensitive_compare)
        debug("Warning: running in case insensitive mode !!!\n");

    atexit(CloseCOM);

    /* Main Loop */
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
        if (NULL == strchr(buf, '\n')) {
            /* too large message received.. skip and deny */
            fprintf(stderr, "%s: ERROR: Too large: %s\n", argv[0], buf);
            while (fgets(buf, HELPER_INPUT_BUFFER, stdin)) {
                fprintf(stderr, "%s: ERROR: Too large..: %s\n", argv[0], buf);
                if (strchr(buf, '\n') != NULL)
                    break;
            }
            SEND_BH(HLP_MSG("Invalid Request. Too Long."));
            continue;
        }
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';      /* strip \n */
        if ((p = strchr(buf, '\r')) != NULL)
            *p = '\0';      /* strip \r */

        debug("Got '%s' from Squid (length: %d).\n", buf, strlen(buf));

        if (buf[0] == '\0') {
            SEND_BH(HLP_MSG("Invalid Request. No Input."));
            continue;
        }
        username = strtok(buf, " ");
        for (n = 0; (group = strtok(nullptr, " ")) != NULL; ++n) {
            rfc1738_unescape(group);
            groups[n] = group;
        }
        groups[n] = nullptr;
        numberofgroups = n;

        if (NULL == username) {
            SEND_BH(HLP_MSG("Invalid Request. No Username."));
            continue;
        }
        rfc1738_unescape(username);

        if ((use_global ? Valid_Global_Groups(username, groups) : Valid_Local_Groups(username, groups))) {
            SEND_OK("");
        } else {
            SEND_ERR("");
        }
        err = 0;
    }
    return EXIT_SUCCESS;
}

