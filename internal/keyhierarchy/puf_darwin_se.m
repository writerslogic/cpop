// Secure Enclave implementation for macOS
// Patent Pending: USPTO Application No. 19/460,364

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

// Check if Secure Enclave is available
int se_available(void) {
    // Check if the device supports Secure Enclave
    // This works on both Apple Silicon and Intel Macs with T2 chip

    // Try to create a temporary key to check availability
    NSDictionary *attributes = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @NO,
        },
    };

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (privateKey != NULL) {
        CFRelease(privateKey);
        return 1; // Available
    }

    if (error != NULL) {
        CFRelease(error);
    }

    return 0; // Not available
}

// Get or create a Secure Enclave key with the given tag
int se_get_or_create_key(const char *key_tag, unsigned char *pub_key_out, int pub_key_len) {
    @autoreleasepool {
        NSString *tag = [NSString stringWithUTF8String:key_tag];
        NSData *tagData = [tag dataUsingEncoding:NSUTF8StringEncoding];

        // First, try to find existing key
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecReturnRef: @YES,
        };

        SecKeyRef privateKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

        if (status != errSecSuccess) {
            // Key doesn't exist, create a new one
            CFErrorRef error = NULL;

            SecAccessControlRef access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAccessControlPrivateKeyUsage,
                &error
            );

            if (error != NULL) {
                CFRelease(error);
                return -1;
            }

            NSDictionary *attributes = @{
                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                (id)kSecAttrKeySizeInBits: @256,
                (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
                (id)kSecPrivateKeyAttrs: @{
                    (id)kSecAttrIsPermanent: @YES,
                    (id)kSecAttrApplicationTag: tagData,
                    (id)kSecAttrAccessControl: (__bridge id)access,
                },
            };

            privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
            CFRelease(access);

            if (error != NULL) {
                CFRelease(error);
                return -1;
            }

            if (privateKey == NULL) {
                return -1;
            }
        }

        // Get public key
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        CFRelease(privateKey);

        if (publicKey == NULL) {
            return -1;
        }

        // Export public key data
        CFErrorRef error = NULL;
        NSData *publicKeyData = (NSData *)CFBridgingRelease(
            SecKeyCopyExternalRepresentation(publicKey, &error)
        );
        CFRelease(publicKey);

        if (error != NULL) {
            CFRelease(error);
            return -1;
        }

        if (publicKeyData == nil || publicKeyData.length > pub_key_len) {
            return -1;
        }

        memcpy(pub_key_out, publicKeyData.bytes, publicKeyData.length);
        return (int)publicKeyData.length;
    }
}

// Sign data using the Secure Enclave key
int se_sign_data(const char *key_tag, const unsigned char *data, int data_len,
                 unsigned char *sig_out, int sig_len) {
    @autoreleasepool {
        NSString *tag = [NSString stringWithUTF8String:key_tag];
        NSData *tagData = [tag dataUsingEncoding:NSUTF8StringEncoding];
        NSData *dataToSign = [NSData dataWithBytes:data length:data_len];

        // Find the key
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecReturnRef: @YES,
        };

        SecKeyRef privateKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

        if (status != errSecSuccess || privateKey == NULL) {
            return -1;
        }

        // Sign the data
        CFErrorRef error = NULL;
        NSData *signature = (NSData *)CFBridgingRelease(
            SecKeyCreateSignature(
                privateKey,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                (__bridge CFDataRef)dataToSign,
                &error
            )
        );
        CFRelease(privateKey);

        if (error != NULL) {
            CFRelease(error);
            return -1;
        }

        if (signature == nil || signature.length > sig_len) {
            return -1;
        }

        memcpy(sig_out, signature.bytes, signature.length);
        return (int)signature.length;
    }
}

// Derive a key from a challenge using the Secure Enclave
// This signs the challenge and uses the signature as derived key material
int se_derive_key(const char *key_tag, const unsigned char *challenge, int challenge_len,
                  unsigned char *derived_out, int derived_len) {
    @autoreleasepool {
        // Use signing as a deterministic derivation function
        // The signature is deterministic for the same key and message
        return se_sign_data(key_tag, challenge, challenge_len, derived_out, derived_len);
    }
}

// Get a unique device identifier
char* se_get_device_id(void) {
    @autoreleasepool {
        // Use IOKit to get the hardware UUID
        // Use kIOMainPortDefault for macOS 12+ compatibility
        mach_port_t mainPort = 0;
#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED >= 120000
        mainPort = kIOMainPortDefault;
#else
        mainPort = kIOMasterPortDefault;
#endif
        io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(mainPort, "IOService:/");
        if (ioRegistryRoot == 0) {
            return NULL;
        }

        CFStringRef uuidCF = (CFStringRef)IORegistryEntryCreateCFProperty(
            ioRegistryRoot,
            CFSTR(kIOPlatformUUIDKey),
            kCFAllocatorDefault,
            0
        );
        IOObjectRelease(ioRegistryRoot);

        if (uuidCF == NULL) {
            return NULL;
        }

        // Use CFRelease instead of __bridge_transfer since ARC is not enabled
        const char *uuidStr = [((__bridge NSString *)uuidCF) UTF8String];
        char *result = NULL;
        if (uuidStr != NULL) {
            result = strdup(uuidStr);
        }
        CFRelease(uuidCF);

        return result;
    }
}

// Free a string allocated by se_get_device_id
void se_free_string(char *s) {
    if (s != NULL) {
        free(s);
    }
}
