// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build darwin && cgo

package sekey

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <Security/Security.h>

// cbbError copies e's description into buf and releases e.
static void cbbError(CFErrorRef e, const char *what, char *buf, size_t n) {
	if (e == NULL) {
		snprintf(buf, n, "%s", what);
		return;
	}
	char desc[200] = "";
	CFStringRef s = CFErrorCopyDescription(e);
	if (s != NULL) {
		CFStringGetCString(s, desc, sizeof desc, kCFStringEncodingUTF8);
		CFRelease(s);
	}
	snprintf(buf, n, "%s: %s (%ld)", what, desc, (long)CFErrorGetCode(e));
	CFRelease(e);
}

// cbbPublic returns the uncompressed point of key's public key.
static CFDataRef cbbPublic(SecKeyRef key, char *err, size_t n) {
	CFErrorRef e = NULL;
	SecKeyRef p = SecKeyCopyPublicKey(key);
	if (p == NULL) {
		cbbError(NULL, "no public key", err, n);
		return NULL;
	}
	CFDataRef d = SecKeyCopyExternalRepresentation(p, &e);
	CFRelease(p);
	if (d == NULL) cbbError(e, "reading the public key", err, n);
	return d;
}

// cbbCreate makes a P-256 key in the Secure Enclave that is not kept in a
// keychain; *blob is the enclave's encrypted copy of it ("toid", what
// CryptoKit calls dataRepresentation), which cbbLoad opens again.
static SecKeyRef cbbCreate(CFDataRef *blob, CFDataRef *pub, char *err, size_t n) {
	CFErrorRef e = NULL;
	// AfterFirstUnlock: the service signs from boot on, before anyone logs
	// in; PrivateKeyUsage asks for no user presence.
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
		kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &e);
	if (ac == NULL) {
		cbbError(e, "the access control", err, n);
		return NULL;
	}
	int bits = 256;
	CFNumberRef nb = CFNumberCreate(NULL, kCFNumberIntType, &bits);
	const void *pk[] = {kSecAttrIsPermanent, kSecAttrAccessControl};
	const void *pv[] = {kCFBooleanFalse, ac};
	CFDictionaryRef priv = CFDictionaryCreate(NULL, pk, pv, 2,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	const void *k[] = {kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecPrivateKeyAttrs};
	const void *v[] = {kSecAttrKeyTypeECSECPrimeRandom, nb, kSecAttrTokenIDSecureEnclave, priv};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 4,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &e);
	CFRelease(attrs);
	CFRelease(priv);
	CFRelease(nb);
	CFRelease(ac);
	if (key == NULL) {
		cbbError(e, "making the key", err, n);
		return NULL;
	}
	CFDictionaryRef a = SecKeyCopyAttributes(key);
	CFTypeRef toid = a == NULL ? NULL : CFDictionaryGetValue(a, CFSTR("toid"));
	if (toid == NULL || CFGetTypeID(toid) != CFDataGetTypeID()) {
		if (a != NULL) CFRelease(a);
		CFRelease(key);
		cbbError(NULL, "the enclave gave no copy of the key to keep", err, n);
		return NULL;
	}
	*blob = CFRetain(toid);
	CFRelease(a);
	*pub = cbbPublic(key, err, n);
	if (*pub == NULL) {
		CFRelease(*blob);
		CFRelease(key);
		return NULL;
	}
	return key;
}

// cbbLoad opens a key from what cbbCreate gave. SecKeyCreateWithData
// would make a new key from it; SecKeyCreateRandomKey with the blob as the
// token's object ID ("toid") opens the one it names, as CryptoKit does.
static SecKeyRef cbbLoad(const void *b, size_t len, CFDataRef *pub, char *err, size_t n) {
	CFErrorRef e = NULL;
	CFDataRef blob = CFDataCreate(NULL, b, (CFIndex)len);
	int bits = 256;
	CFNumberRef nb = CFNumberCreate(NULL, kCFNumberIntType, &bits);
	const void *k[] = {kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, CFSTR("toid"), kSecAttrIsPermanent};
	const void *v[] = {kSecAttrKeyTypeECSECPrimeRandom, nb, kSecAttrTokenIDSecureEnclave, blob, kCFBooleanFalse};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 5,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &e);
	CFRelease(attrs);
	CFRelease(nb);
	CFRelease(blob);
	if (key == NULL) {
		cbbError(e, "opening the key", err, n);
		return NULL;
	}
	*pub = cbbPublic(key, err, n);
	if (*pub == NULL) {
		CFRelease(key);
		return NULL;
	}
	return key;
}

// cbbSign signs a SHA-256, SHA-384 or SHA-512 digest, by its length.
static CFDataRef cbbSign(SecKeyRef key, const void *d, size_t len, char *err, size_t n) {
	SecKeyAlgorithm alg;
	switch (len) {
	case 32: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256; break;
	case 48: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384; break;
	case 64: alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA512; break;
	default:
		cbbError(NULL, "a digest of the wrong length", err, n);
		return NULL;
	}
	CFErrorRef e = NULL;
	CFDataRef digest = CFDataCreate(NULL, d, (CFIndex)len);
	CFDataRef sig = SecKeyCreateSignature(key, alg, digest, &e);
	CFRelease(digest);
	if (sig == NULL) cbbError(e, "signing", err, n);
	return sig;
}

// cbbAgree agrees on a secret between key and the uncompressed point pub
// (ECDH, the shared X coordinate).
static CFDataRef cbbAgree(SecKeyRef key, const void *p, size_t len, char *err, size_t n) {
	CFErrorRef e = NULL;
	CFDataRef data = CFDataCreate(NULL, p, (CFIndex)len);
	const void *k[] = {kSecAttrKeyType, kSecAttrKeyClass};
	const void *v[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 2,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecKeyRef pub = SecKeyCreateWithData(data, attrs, &e);
	CFRelease(attrs);
	CFRelease(data);
	if (pub == NULL) {
		cbbError(e, "reading the other public key", err, n);
		return NULL;
	}
	CFDictionaryRef params = CFDictionaryCreate(NULL, NULL, NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDataRef shared = SecKeyCopyKeyExchangeResult(key, kSecKeyAlgorithmECDHKeyExchangeStandard, pub, params, &e);
	CFRelease(params);
	CFRelease(pub);
	if (shared == NULL) cbbError(e, "agreeing on a secret", err, n);
	return shared;
}

static void cbbRelease(CFTypeRef r) { CFRelease(r); }
*/
import "C"

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// ref is a loaded key; the runtime releases it when its Key goes.
type ref struct{ h *handle }

type handle struct{ key C.SecKeyRef }

func (r ref) release() {
	if r.h != nil && r.h.key != 0 {
		C.cbbRelease(C.CFTypeRef(r.h.key))
		r.h.key = 0
	}
}

func newRef(key C.SecKeyRef) ref {
	h := &handle{key: key}
	runtime.AddCleanup(h, func(k C.SecKeyRef) { C.cbbRelease(C.CFTypeRef(k)) }, key)
	return ref{h: h}
}

func (r ref) sign(digest []byte) ([]byte, error) {
	var buf [256]C.char
	sig := C.cbbSign(r.h.key, unsafe.Pointer(&digest[0]), C.size_t(len(digest)), &buf[0], C.size_t(len(buf)))
	runtime.KeepAlive(r.h)
	if sig == 0 {
		return nil, errors.New("sekey: " + C.GoString(&buf[0]))
	}
	return data(sig), nil
}

func (r ref) agree(pub []byte) ([]byte, error) {
	var buf [256]C.char
	shared := C.cbbAgree(r.h.key, unsafe.Pointer(&pub[0]), C.size_t(len(pub)), &buf[0], C.size_t(len(buf)))
	runtime.KeepAlive(r.h)
	if shared == 0 {
		return nil, errors.New("sekey: " + C.GoString(&buf[0]))
	}
	return data(shared), nil
}

// data copies d and releases it.
func data(d C.CFDataRef) []byte {
	defer C.cbbRelease(C.CFTypeRef(d))
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(d)), C.int(C.CFDataGetLength(d)))
}

var (
	availOnce sync.Once
	avail     bool
)

// available makes one key, which no keychain keeps, to see whether the
// enclave is there.
func available() bool {
	availOnce.Do(func() {
		r, _, _, err := create()
		if err == nil {
			r.release()
			avail = true
		}
	})
	return avail
}

func create() (ref, []byte, []byte, error) {
	var buf [256]C.char
	var blob, pub C.CFDataRef
	key := C.cbbCreate(&blob, &pub, &buf[0], C.size_t(len(buf)))
	if key == 0 {
		return ref{}, nil, nil, errors.New("sekey: " + C.GoString(&buf[0]))
	}
	return newRef(key), data(blob), data(pub), nil
}

func load(blob []byte) (ref, []byte, error) {
	if len(blob) == 0 {
		return ref{}, nil, errors.New("sekey: an empty key")
	}
	var buf [256]C.char
	var pub C.CFDataRef
	key := C.cbbLoad(unsafe.Pointer(&blob[0]), C.size_t(len(blob)), &pub, &buf[0], C.size_t(len(buf)))
	if key == 0 {
		return ref{}, nil, errors.New("sekey: " + C.GoString(&buf[0]))
	}
	return newRef(key), data(pub), nil
}
