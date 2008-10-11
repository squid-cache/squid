// Copyright (C) 2002 Microsoft Corporation
// All rights reserved.
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS"
// WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
// OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE IMPLIED WARRANTIES OF MERCHANTIBILITY
// AND/OR FITNESS FOR A PARTICULAR PURPOSE.
//
// Date    - 10/08/2002
// Author  - Sanj Surati

/////////////////////////////////////////////////////////////
//
// SPNEGOPARSE.H
//
// SPNEGO Token Parser Header File
//
// Contains the definitions required to properly parse a
// SPNEGO token using ASN.1 DER helpers.
//
/////////////////////////////////////////////////////////////

#ifndef __SPNEGOPARSE_H__
#define __SPNEGOPARSE_H__

// C++ Specific
#if defined(__cplusplus)
extern "C"
{
#endif

// Indicates if we copy data when creating a SPNEGO_TOKEN structure or not
#define SPNEGO_TOKEN_INTERNAL_COPYPTR           0
#define SPNEGO_TOKEN_INTERNAL_COPYDATA          0x1

// Internal flag dictates whether or not we will free the binary data when
// the SPNEG_TOKEN structure is destroyed
#define  SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA   0x1

    //
// Each SPNEGO Token Type can be broken down into a
// maximum of 4 separate elements.
//

#define  MAX_NUM_TOKEN_ELEMENTS  4

//
// Element offsets in the array
//

// INIT elements
#define  SPNEGO_INIT_MECHTYPES_ELEMENT    0
#define  SPNEGO_INIT_REQFLAGS_ELEMENT     1
#define  SPNEGO_INIT_MECHTOKEN_ELEMENT    2
#define  SPNEGO_INIT_MECHLISTMIC_ELEMENT  3

// Response elements
#define  SPNEGO_TARG_NEGRESULT_ELEMENT    0
#define  SPNEGO_TARG_SUPPMECH_ELEMENT     1
#define  SPNEGO_TARG_RESPTOKEN_ELEMENT    2
#define  SPNEGO_TARG_MECHLISTMIC_ELEMENT  3

//
// Defines an individual SPNEGO Token Element.
//

    typedef struct SpnegoElement {
        size_t                nStructSize;        // Size of the element structure
        int                   iElementPresent;    // Is the field present?  Must be either
        // SPNEGO_TOKEN_ELEMENT_UNAVAILABLE or
        // SPNEGO_TOKEN_ELEMENT_AVAILABLE

        SPNEGO_ELEMENT_TYPE   eElementType;       // The Element Type

        unsigned char         type;               // Data Type

        unsigned char*        pbData;             // Points to actual Data

        unsigned long         nDatalength;        // Actual Data Length

    } SPNEGO_ELEMENT;

// Structure size in case we later choose to extend the structure
#define  SPNEGO_ELEMENT_SIZE sizeof(SPNEGO_ELEMENT)

//
// Packages a SPNEGO Token Encoding.  There are two types of
// encodings: NegTokenInit and NegTokenTarg.  Each encoding can
// contain up to four distinct, optional elements.
//

    typedef struct SpnegoToken {
        size_t            nStructSize;                              // Size of the Token structure
        unsigned long     ulFlags;                                  // Internal Structure Flags - Reserved!
        int               ucTokenType;                              // Token Type - Must be
        // SPNEGO_TOKEN_INIT or
        // SPNEGO_TOKEN_TARG

        unsigned char*    pbBinaryData;                             // Points to binary token data

        unsigned long     ulBinaryDataLen;                          // Length of the actual binary data
        int               nNumElements;                             // Number of elements
        SPNEGO_ELEMENT    aElementArray [MAX_NUM_TOKEN_ELEMENTS];   // Holds the elements for the token
    } SPNEGO_TOKEN;

// Structure size in case we later choose to extend the structure
#define  SPNEGO_TOKEN_SIZE sizeof(SPNEGO_TOKEN)

//
// Function definitions
//

    SPNEGO_TOKEN* AllocEmptySpnegoToken( unsigned char ucCopyData, unsigned long ulFlags,
                                         unsigned char * pbTokenData, unsigned long ulTokenSize );
    void FreeSpnegoToken( SPNEGO_TOKEN* pSpnegoToken );
    void InitSpnegoTokenElementArray( SPNEGO_TOKEN* pSpnegoToken );
    int InitSpnegoTokenType( SPNEGO_TOKEN* pSpnegoToken, long* pnTokenLength,
                             long* pnRemainingTokenLength, unsigned char** ppbFirstElement );
    int InitSpnegoTokenElements( SPNEGO_TOKEN* pSpnegoToken, unsigned char* pbTokenData,
                                 long nRemainingTokenLength  );
    int GetSpnegoInitTokenMechList( unsigned char* pbTokenData, int nMechListLength,
                                    SPNEGO_ELEMENT* pSpnegoElement );
    int InitSpnegoTokenElementFromBasicType( unsigned char* pbTokenData, int nElementLength,
            unsigned char ucExpectedType,
            SPNEGO_ELEMENT_TYPE spnegoElementType,
            SPNEGO_ELEMENT* pSpnegoElement );
    int InitSpnegoTokenElementFromOID( unsigned char* pbTokenData, int nElementLength,
                                       SPNEGO_ELEMENT_TYPE spnegoElementType,
                                       SPNEGO_ELEMENT* pSpnegoElement );
    int FindMechOIDInMechList( SPNEGO_ELEMENT* pSpnegoElement, SPNEGO_MECH_OID MechOID,
                               int * piMechTypeIndex );
    int ValidateMechList( unsigned char* pbMechListData, long nBoundaryLength );
    int CalculateMinSpnegoInitTokenSize( long nMechTokenLength, long nMechListMICLength,
                                         SPNEGO_MECH_OID mechOid, int nReqFlagsAvailable,
                                         long* plTokenSize, long* plInternalLength );
    int CalculateMinSpnegoTargTokenSize( SPNEGO_MECH_OID MechType, SPNEGO_NEGRESULT spnegoNegResult,
                                         long nMechTokenLen,
                                         long nMechTokenMIC, long* pnTokenSize,
                                         long* pnInternalTokenLength );
    int CreateSpnegoInitToken( SPNEGO_MECH_OID MechType,
                               unsigned char ucContextFlags, unsigned char* pbMechToken,
                               unsigned long ulMechTokenLen, unsigned char* pbMechListMIC,
                               unsigned long ulMechListMICLen, unsigned char* pbTokenData,
                               long nTokenLength, long nInternalTokenLength );
    int CreateSpnegoTargToken( SPNEGO_MECH_OID MechType,
                               SPNEGO_NEGRESULT eNegResult, unsigned char* pbMechToken,
                               unsigned long ulMechTokenLen, unsigned char* pbMechListMIC,
                               unsigned long ulMechListMICLen, unsigned char* pbTokenData,
                               long nTokenLength, long nInternalTokenLength );
    int IsValidMechOid( SPNEGO_MECH_OID mechOid );
    int IsValidContextFlags( unsigned char ucContextFlags );
    int IsValidNegResult( SPNEGO_NEGRESULT negResult );
    int IsValidSpnegoToken( SPNEGO_TOKEN* pSpnegoToken );
    int IsValidSpnegoElement( SPNEGO_TOKEN* pSpnegoToken,SPNEGO_ELEMENT_TYPE spnegoElement );
    int CalculateElementArrayIndex( SPNEGO_TOKEN* pSpnegoToken,SPNEGO_ELEMENT_TYPE spnegoElement );
    int InitTokenFromBinary( unsigned char ucCopyData, unsigned long ulFlags,
                             unsigned char* pbTokenData, unsigned long ulLength,
                             SPNEGO_TOKEN** ppSpnegoToken );

    // C++ Specific
#if defined(__cplusplus)
}
#endif

#endif

