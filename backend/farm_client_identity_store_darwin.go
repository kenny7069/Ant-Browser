//go:build darwin && cgo

package backend

/*
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef farmString(const char *value) {
	return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static OSStatus farmKeychainCopy(const char *service, const char *account, void **bytes, CFIndex *length) {
	CFStringRef serviceRef = farmString(service);
	CFStringRef accountRef = farmString(account);
	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
	const void *values[] = {kSecClassGenericPassword, serviceRef, accountRef, kCFBooleanTrue, kSecMatchLimitOne};
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	if (status == errSecSuccess) {
		CFDataRef data = (CFDataRef)result;
		*length = CFDataGetLength(data);
		*bytes = malloc((size_t)*length);
		if (*bytes == NULL || *length <= 0) {
			if (*bytes != NULL) free(*bytes);
			*bytes = NULL;
			status = errSecAllocate;
		} else {
			memcpy(*bytes, CFDataGetBytePtr(data), (size_t)*length);
		}
	}
	if (result != NULL) CFRelease(result);
	if (query != NULL) CFRelease(query);
	if (serviceRef != NULL) CFRelease(serviceRef);
	if (accountRef != NULL) CFRelease(accountRef);
	return status;
}

static OSStatus farmKeychainSave(const char *service, const char *account, const void *bytes, CFIndex length) {
	CFStringRef serviceRef = farmString(service);
	CFStringRef accountRef = farmString(account);
	CFDataRef data = CFDataCreate(NULL, bytes, length);
	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible};
	const void *values[] = {kSecClassGenericPassword, serviceRef, accountRef, data, kSecAttrAccessibleWhenUnlockedThisDeviceOnly};
	CFDictionaryRef item = CFDictionaryCreate(NULL, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus status = SecItemAdd(item, NULL);
	if (item != NULL) CFRelease(item);
	if (data != NULL) CFRelease(data);
	if (serviceRef != NULL) CFRelease(serviceRef);
	if (accountRef != NULL) CFRelease(accountRef);
	return status;
}

static OSStatus farmKeychainDelete(const char *service, const char *account) {
	CFStringRef serviceRef = farmString(service);
	CFStringRef accountRef = farmString(account);
	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
	const void *values[] = {kSecClassGenericPassword, serviceRef, accountRef};
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus status = SecItemDelete(query);
	if (query != NULL) CFRelease(query);
	if (serviceRef != NULL) CFRelease(serviceRef);
	if (accountRef != NULL) CFRelease(accountRef);
	return status;
}

static void farmKeychainFree(void *bytes) {
	free(bytes);
}

static OSStatus farmErrSecSuccess(void) { return errSecSuccess; }
static OSStatus farmErrSecItemNotFound(void) { return errSecItemNotFound; }
static OSStatus farmErrSecDuplicateItem(void) { return errSecDuplicateItem; }
*/
import "C"

import (
	"crypto/ed25519"
	"errors"
	"unsafe"
)

const farmClientIdentityKeychainService = "ant-browser/farm-client/device-key/v1"

func NewFarmClientIdentityStore(root string) (FarmClientIdentityStore, error) {
	if err := validateFarmClientIdentityStoreRoot(root); err != nil {
		return nil, err
	}
	return &darwinFarmClientIdentityStore{}, nil
}

type darwinFarmClientIdentityStore struct{}

func (s *darwinFarmClientIdentityStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return nil, err
	}
	service := C.CString(farmClientIdentityKeychainService)
	account := C.CString(string(ref))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	var bytes unsafe.Pointer
	var length C.CFIndex
	status := C.farmKeychainCopy(service, account, &bytes, &length)
	if status != C.farmErrSecSuccess() {
		if status == C.farmErrSecItemNotFound() {
			return nil, ErrFarmClientIdentityKeyNotFound
		}
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	decrypted := C.GoBytes(bytes, C.int(length))
	C.farmKeychainFree(bytes)
	key, seed, err := normalizeFarmClientIdentityKey(decrypted)
	clearBytes(decrypted)
	if seed != nil {
		clearBytes(seed)
	}
	if err != nil {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	return key, nil
}

func (s *darwinFarmClientIdentityStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	normalized, seed, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	defer clearBytes(normalized)
	defer clearBytes(seed)
	if existing, loadErr := s.Load(ref); loadErr == nil {
		defer clearBytes(existing)
		if equalBytes(existing[:ed25519.SeedSize], seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	} else if !errors.Is(loadErr, ErrFarmClientIdentityKeyNotFound) {
		return farmClientIdentityStoreError(loadErr)
	}
	service := C.CString(farmClientIdentityKeychainService)
	account := C.CString(string(ref))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	status := C.farmKeychainSave(service, account, unsafe.Pointer(&seed[0]), C.CFIndex(len(seed)))
	if status == C.farmErrSecDuplicateItem() {
		return s.Save(ref, seed)
	}
	if status != C.farmErrSecSuccess() {
		return ErrFarmClientIdentityStoreUnavailable
	}
	return nil
}

func (s *darwinFarmClientIdentityStore) Delete(ref FarmClientIdentityKeyRef) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	service := C.CString(farmClientIdentityKeychainService)
	account := C.CString(string(ref))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	status := C.farmKeychainDelete(service, account)
	if status == C.farmErrSecSuccess() || status == C.farmErrSecItemNotFound() {
		return nil
	}
	return ErrFarmClientIdentityStoreUnavailable
}
