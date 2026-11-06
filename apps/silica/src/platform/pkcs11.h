// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The part of PKCS#11 2.40 the app uses, with the Linux ABI (no packing), for
// OP-TEE's libckteec, which the app opens at run time: Sailfish OS and phones
// without a TEE have none.
#pragma once

namespace pkcs11 {

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef unsigned char CK_BBOOL;

struct CK_VERSION { unsigned char major, minor; };
struct CK_TOKEN_INFO {
    unsigned char label[32], manufacturerID[32], model[16], serialNumber[16];
    CK_ULONG flags, ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount,
        ulMaxPinLen, ulMinPinLen, ulTotalPublicMemory, ulFreePublicMemory,
        ulTotalPrivateMemory, ulFreePrivateMemory;
    CK_VERSION hardwareVersion, firmwareVersion;
    unsigned char utcTime[16];
};
struct CK_ATTRIBUTE { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; };
struct CK_MECHANISM { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; };

typedef CK_RV (*Unused)();
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(void *);
    CK_RV (*C_Finalize)(void *);
    Unused C_GetInfo, C_GetFunctionList;
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);
    Unused C_GetSlotInfo;
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO *);
    Unused C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN;
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    Unused C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState, C_SetOperationState;
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, const unsigned char *, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    Unused C_CreateObject, C_CopyObject;
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    Unused C_GetObjectSize;
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    Unused C_SetAttributeValue;
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    Unused C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal, C_DecryptInit, C_Decrypt,
        C_DecryptUpdate, C_DecryptFinal, C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey,
        C_DigestFinal;
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, const unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    Unused C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover, C_VerifyInit, C_Verify,
        C_VerifyUpdate, C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover, C_DigestEncryptUpdate,
        C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate, C_GenerateKey;
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                               CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
};

// Return values.
const CK_RV CKR_OK = 0x0;
const CK_RV CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191;
const CK_RV CKR_USER_ALREADY_LOGGED_IN = 0x100;

// Token flags.
const CK_ULONG CKF_LOGIN_REQUIRED = 0x4;
const CK_ULONG CKF_USER_PIN_INITIALIZED = 0x8;
const CK_ULONG CKF_TOKEN_INITIALIZED = 0x400;
const CK_ULONG CKF_USER_PIN_COUNT_LOW = 0x10000;
const CK_ULONG CKF_USER_PIN_FINAL_TRY = 0x20000;
const CK_ULONG CKF_USER_PIN_LOCKED = 0x40000;

// Sessions and users.
const CK_ULONG CKF_RW_SESSION = 0x2;
const CK_ULONG CKF_SERIAL_SESSION = 0x4;
const CK_ULONG CKU_USER = 1;

// Attributes.
const CK_ULONG CKA_CLASS = 0x0;
const CK_ULONG CKA_TOKEN = 0x1;
const CK_ULONG CKA_PRIVATE = 0x2;
const CK_ULONG CKA_LABEL = 0x3;
const CK_ULONG CKA_ID = 0x102;
const CK_ULONG CKA_SENSITIVE = 0x103;
const CK_ULONG CKA_SIGN = 0x108;
const CK_ULONG CKA_VERIFY = 0x10A;
const CK_ULONG CKA_EXTRACTABLE = 0x162;
const CK_ULONG CKA_NEVER_EXTRACTABLE = 0x164;
const CK_ULONG CKA_ALWAYS_SENSITIVE = 0x165;
const CK_ULONG CKA_EC_PARAMS = 0x180;
const CK_ULONG CKA_EC_POINT = 0x181;

// Classes and mechanisms.
const CK_ULONG CKO_PUBLIC_KEY = 2;
const CK_ULONG CKO_PRIVATE_KEY = 3;
const CK_ULONG CKM_EC_KEY_PAIR_GEN = 0x1040;
const CK_ULONG CKM_ECDSA = 0x1041;

} // namespace pkcs11
