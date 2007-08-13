/* 
 * Copyright (C) 2002-2004 Novell, Inc.
 *
 * edir_ldapext.c  LDAP extension for reading eDirectory universal password
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail, you may
 * find current contact  information at www.novell.com.
 */

#include "digest_common.h"

#ifdef _SQUID_MSWIN_		/* Native Windows port and MinGW */

#define snprintf _snprintf
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#ifndef LDAPAPI
#define LDAPAPI __cdecl
#endif
#ifdef LDAP_VERSION3
#ifndef LDAP_OPT_X_TLS
#define LDAP_OPT_X_TLS 0x6000
#endif
#define ber_alloc() ber_alloc_t(0)
#endif /* LDAP_VERSION3 */

#else

#include <lber.h>
#include <ldap.h>

#endif

#include "edir_ldapext.h"

/* NMAS error codes */
#define NMAS_E_BASE                       (-1600)

#define NMAS_SUCCESS                      0
#define NMAS_E_SUCCESS                    NMAS_SUCCESS	/* Alias  */
#define NMAS_OK                           NMAS_SUCCESS	/* Alias  */

#define NMAS_E_FRAG_FAILURE               (NMAS_E_BASE-31)	/* -1631 0xFFFFF9A1 */
#define NMAS_E_BUFFER_OVERFLOW            (NMAS_E_BASE-33)	/* -1633 0xFFFFF99F */
#define NMAS_E_SYSTEM_RESOURCES           (NMAS_E_BASE-34)	/* -1634 0xFFFFF99E */
#define NMAS_E_INSUFFICIENT_MEMORY        (NMAS_E_BASE-35)	/* -1635 0xFFFFF99D */
#define NMAS_E_NOT_SUPPORTED              (NMAS_E_BASE-36)	/* -1636 0xFFFFF99C */
#define NMAS_E_INVALID_PARAMETER          (NMAS_E_BASE-43)	/* -1643 0xFFFFF995 */
#define NMAS_E_INVALID_VERSION            (NMAS_E_BASE-52)	/* -1652 0xFFFFF98C */

/* OID of LDAP extenstion calls to read Universal Password */
#define NMASLDAP_GET_PASSWORD_REQUEST         "2.16.840.1.113719.1.39.42.100.13"
#define NMASLDAP_GET_PASSWORD_RESPONSE        "2.16.840.1.113719.1.39.42.100.14"

#define NMAS_LDAP_EXT_VERSION 1



/* ------------------------------------------------------------------------
 *    berEncodePasswordData
 *      ==============================
 *      RequestBer contents:
 *              clientVersion                           INTEGER
 *              targetObjectDN                          OCTET STRING
 *              password1                                       OCTET STRING
 *              password2                                       OCTET STRING
 *
 *      Description:
 *              This function takes the request BER value and input data items
 *              and BER encodes the data into the BER value
 *
 * ------------------------------------------------------------------------ */
int 
berEncodePasswordData(
    struct berval **requestBV,
    char *objectDN,
    char *password,
    char *password2)
{
    int err = 0, rc = 0;
    BerElement *requestBer = NULL;

    char *utf8ObjPtr = NULL;
    int utf8ObjSize = 0;
    char *utf8PwdPtr = NULL;
    int utf8PwdSize = 0;
    char *utf8Pwd2Ptr = NULL;
    int utf8Pwd2Size = 0;


    utf8ObjSize = strlen(objectDN) + 1;
    utf8ObjPtr = objectDN;

    if (password != NULL) {
	utf8PwdSize = strlen(password) + 1;
	utf8PwdPtr = password;
    }
    if (password2 != NULL) {
	utf8Pwd2Size = strlen(password2) + 1;
	utf8Pwd2Ptr = password2;
    }
    /* Allocate a BerElement for the request parameters. */
    if ((requestBer = ber_alloc()) == NULL) {
	err = NMAS_E_FRAG_FAILURE;
	goto Cleanup;
    }
    if (password != NULL && password2 != NULL) {
	/* BER encode the NMAS Version, the objectDN, and the password */
	rc = ber_printf(requestBer, "{iooo}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize, utf8PwdPtr, utf8PwdSize, utf8Pwd2Ptr, utf8Pwd2Size);
    } else if (password != NULL) {
	/* BER encode the NMAS Version, the objectDN, and the password */
	rc = ber_printf(requestBer, "{ioo}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize, utf8PwdPtr, utf8PwdSize);
    } else {
	/* BER encode the NMAS Version and the objectDN */
	rc = ber_printf(requestBer, "{io}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize);
    }

    if (rc < 0) {
	err = NMAS_E_FRAG_FAILURE;
	goto Cleanup;
    } else {
	err = 0;
    }

    /* 
     * Convert the BER we just built to a berval that we'll send with the extended request. 
     */
    if (ber_flatten(requestBer, requestBV) == LBER_ERROR) {
	err = NMAS_E_FRAG_FAILURE;
	goto Cleanup;
    }
  Cleanup:

    if (requestBer) {
	ber_free(requestBer, 1);
    }
    return err;
}				/* End of berEncodePasswordData */

/* ------------------------------------------------------------------------
 *    berDecodeLoginData()
 *      ==============================
 *      ResponseBer contents:
 *              serverVersion                           INTEGER
 *              error                                   INTEGER
 *              data                                            OCTET STRING
 *
 *      Description:
 *              This function takes the reply BER Value and decodes the
 *              NMAS server version and return code and if a non null retData
 *              buffer was supplied, tries to decode the the return data and length
 *
 * ------------------------------------------------------------------------ */
int 
berDecodeLoginData(
    struct berval *replyBV,
    int *serverVersion,
    size_t * retDataLen,
    void *retData)
{
    int rc = 0, err = 0;
    BerElement *replyBer = NULL;
    char *retOctStr = NULL;
    size_t retOctStrLen = 0;

    if ((replyBer = ber_init(replyBV)) == NULL) {
	err = NMAS_E_SYSTEM_RESOURCES;
	goto Cleanup;
    }
    if (retData) {
	retOctStrLen = *retDataLen + 1;
	retOctStr = (char *) malloc(retOctStrLen);
	if (!retOctStr) {
	    err = NMAS_E_SYSTEM_RESOURCES;
	    goto Cleanup;
	}
	if ((rc = ber_scanf(replyBer, "{iis}", serverVersion, &err, retOctStr, &retOctStrLen)) != -1) {
	    if (*retDataLen >= retOctStrLen) {
		memcpy(retData, retOctStr, retOctStrLen);
	    } else if (!err) {
		err = NMAS_E_BUFFER_OVERFLOW;
	    }
	    *retDataLen = retOctStrLen;
	} else if (!err) {
	    err = NMAS_E_FRAG_FAILURE;
	}
    } else {
	if ((rc = ber_scanf(replyBer, "{ii}", serverVersion, &err)) == -1) {
	    if (!err) {
		err = NMAS_E_FRAG_FAILURE;
	    }
	}
    }

  Cleanup:

    if (replyBer) {
	ber_free(replyBer, 1);
    }
    if (retOctStr != NULL) {
	memset(retOctStr, 0, retOctStrLen);
	free(retOctStr);
    }
    return err;
}				/* End of berDecodeLoginData */

/* -----------------------------------------------------------------------
 *    nmasldap_get_password()
 *      ==============================
 *
 *      Description:
 *              This API attempts to get the universal password
 *
 * ------------------------------------------------------------------------ */
int 
nmasldap_get_password(
    LDAP * ld,
    char *objectDN,
    size_t * pwdSize,		// in bytes
     char *pwd)
{
    int err = 0;

    struct berval *requestBV = NULL;
    char *replyOID = NULL;
    struct berval *replyBV = NULL;
    int serverVersion;
    char *pwdBuf;
    size_t pwdBufLen, bufferLen;

#ifdef	NOT_N_PLAT_NLM
    int currentThreadGroupID;
#endif

    /* Validate char    parameters. */
    if (objectDN == NULL || (strlen(objectDN) == 0) || pwdSize == NULL || ld == NULL) {
	return NMAS_E_INVALID_PARAMETER;
    }
    bufferLen = pwdBufLen = *pwdSize;
    pwdBuf = (char *) malloc(pwdBufLen + 2);
    if (pwdBuf == NULL) {
	return NMAS_E_INSUFFICIENT_MEMORY;
    }
#ifdef	NOT_N_PLAT_NLM
    currentThreadGroupID = SetThreadGroupID(nmasLDAPThreadGroupID);
#endif

    err = berEncodePasswordData(&requestBV, objectDN, NULL, NULL);
    if (err) {
	goto Cleanup;
    }
    /* Call the ldap_extended_operation (synchronously) */
    if ((err = ldap_extended_operation_s(ld, NMASLDAP_GET_PASSWORD_REQUEST, requestBV, NULL, NULL, &replyOID, &replyBV))) {
	goto Cleanup;
    }
    /* Make sure there is a return OID */
    if (!replyOID) {
	err = NMAS_E_NOT_SUPPORTED;
	goto Cleanup;
    }
    /* Is this what we were expecting to get back. */
    if (strcmp(replyOID, NMASLDAP_GET_PASSWORD_RESPONSE)) {
	err = NMAS_E_NOT_SUPPORTED;
	goto Cleanup;
    }
    /* Do we have a good returned berval? */
    if (!replyBV) {
	/* 
	 * No; returned berval means we experienced a rather drastic error.
	 * Return operations error.
	 */
	err = NMAS_E_SYSTEM_RESOURCES;
	goto Cleanup;
    }
    err = berDecodeLoginData(replyBV, &serverVersion, &pwdBufLen, pwdBuf);

    if (serverVersion != NMAS_LDAP_EXT_VERSION) {
	err = NMAS_E_INVALID_VERSION;
	goto Cleanup;
    }
    if (!err && pwdBufLen != 0) {
	if (*pwdSize >= pwdBufLen + 1 && pwd != NULL) {
	    memcpy(pwd, pwdBuf, pwdBufLen);
	    pwd[pwdBufLen] = 0;	/* add null termination */
	}
	*pwdSize = pwdBufLen;	/* does not include null termination */
    }
  Cleanup:

    if (replyBV) {
	ber_bvfree(replyBV);
    }
    /* Free the return OID string if one was returned. */
    if (replyOID) {
	ldap_memfree(replyOID);
    }
    /* Free memory allocated while building the request ber and berval. */
    if (requestBV) {
	ber_bvfree(requestBV);
    }
    if (pwdBuf != NULL) {
	memset(pwdBuf, 0, bufferLen);
	free(pwdBuf);
    }
#ifdef	NOT_N_PLAT_NLM
    SetThreadGroupID(currentThreadGroupID);
#endif

    /* Return the appropriate error/success code. */
    return err;
}				/* end of nmasldap_get_password */
