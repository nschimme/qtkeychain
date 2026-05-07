/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

/*
 * Note for Face ID support:
 * To use Face ID, apps using this library must include the NSFaceIDUsageDescription
 * key in their Info.plist file.
 */

using namespace QKeychain;

struct ErrorDescription
{
    QKeychain::Error code;
    QString message;

    ErrorDescription(QKeychain::Error code, const QString &message) : code(code), message(message)
    {
    }

    static ErrorDescription fromStatus(OSStatus status)
    {
        switch (status) {
        case errSecSuccess:
            return ErrorDescription(QKeychain::NoError, Job::tr("No error"));
        case errSecItemNotFound:
            return ErrorDescription(
                    QKeychain::EntryNotFound,
                    Job::tr("The specified item could not be found in the keychain"));
        case errSecUserCanceled:
            return ErrorDescription(QKeychain::AccessDeniedByUser,
                                    Job::tr("User canceled the operation"));
        case errSecInteractionNotAllowed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("User interaction is not allowed"));
        case errSecNotAvailable:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("No keychain is available. You may need to restart your computer"));
        case errSecAuthFailed:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("The user name or passphrase you entered is not correct"));
        case errSecVerifyFailed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("A cryptographic verification failure has occurred"));
        case errSecUnimplemented:
            return ErrorDescription(QKeychain::NotImplemented,
                                    Job::tr("Function or operation not implemented"));
        case errSecIO:
            return ErrorDescription(QKeychain::OtherError, Job::tr("I/O error"));
        case errSecOpWr:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Already open with with write permission"));
        case errSecParam:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Invalid parameters passed to a function"));
        case errSecAllocate:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Failed to allocate memory"));
        case errSecBadReq:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Bad parameter or invalid state for operation"));
        case errSecInternalComponent:
            return ErrorDescription(QKeychain::OtherError, Job::tr("An internal component failed"));
        case errSecDuplicateItem:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("The specified item already exists in the keychain"));
        case errSecDecode:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Unable to decode the provided data"));
        }

        return ErrorDescription(QKeychain::OtherError, Job::tr("Unknown error"));
    }
};

@interface AppleKeychainInterface : NSObject

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob;
- (void)keychainTaskFinished;
- (void)keychainReadTaskFinished:(NSData *)retrievedData;
- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage;

@end

@interface AppleKeychainInterface () {
    QPointer<Job> _job;
    QPointer<JobPrivate> _privateJob;
    LAContext *_context;
}
@end

@implementation AppleKeychainInterface

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob
{
    self = [super init];
    if (self) {
        _job = job;
        _privateJob = privateJob;
        _context = [[LAContext alloc] init];
    }
    return self;
}

- (void)dealloc
{
    [_context release];
    [NSNotificationCenter.defaultCenter removeObserver:self];
    [super dealloc];
}

- (LAContext *)context
{
    return _context;
}

- (QKeychain::Job::SecurityLevel)effectiveSecurityLevel
{
    if (!_job || _job->securityLevel() != QKeychain::Job::Biometric) {
        return QKeychain::Job::Standard;
    }

    NSError *error = nil;
    if ([_context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
        return QKeychain::Job::Biometric;
    }

    return QKeychain::Job::Standard;
}


- (void)keychainTaskFinished
{
    if (_job) {
        _job->emitFinished();
    }
}

- (void)keychainReadTaskFinished:(NSData *)retrievedData
{
    if (_privateJob) {
        _privateJob->data.clear();
        _privateJob->mode = JobPrivate::Binary;
        if (retrievedData != nil) {
            _privateJob->data = QByteArray::fromNSData(retrievedData);
        }
    }

    if (_job) {
        _job->emitFinished();
    }
}

- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage
{
    const auto localisedDescriptiveMessage = Job::tr([descriptiveMessage UTF8String]);

    const ErrorDescription error = ErrorDescription::fromStatus(status);
    const auto fullMessage = localisedDescriptiveMessage.isEmpty()
            ? error.message
            : QStringLiteral("%1: %2").arg(localisedDescriptiveMessage, error.message);

    if (_job) {
        _job->emitFinishedWithError(error.code, fullMessage);
    }
}

@end

static void StartReadPassword(const QString &service, const QString &key,
                              AppleKeychainInterface *const interface)
{
    const auto securityLevel = [interface effectiveSecurityLevel];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSMutableDictionary *const query = [NSMutableDictionary dictionaryWithDictionary:@{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecAttrAccount : key.toNSString(),
            (__bridge NSString *)kSecReturnData : @YES,
        }];

        if (securityLevel == QKeychain::Job::Biometric) {
            const auto prompt = Job::tr("Authenticate to access %1").arg(service);
            [query setObject:prompt.toNSString() forKey:(__bridge NSString *)kSecUseOperationPrompt];
            [query setObject:[interface context] forKey:(__bridge NSString *)kSecUseAuthenticationContext];
        }

        CFTypeRef dataRef = nil;
        const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataRef);

        if (status == errSecSuccess) {
            const CFDataRef castedDataRef = (CFDataRef)dataRef;
            NSData *const data = (__bridge NSData *)castedDataRef;
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainReadTaskFinished:data];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString =
                    @"Could not retrieve private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }

        if (dataRef) {
            CFRelease(dataRef);
        }
    });
}

static void StartWritePassword(const QString &service, const QString &key, const QByteArray &data,
                               AppleKeychainInterface *const interface)
{
    const auto securityLevel = [interface effectiveSecurityLevel];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSMutableDictionary *const query = [NSMutableDictionary dictionaryWithDictionary:@{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecAttrAccount : key.toNSString(),
        }];

        if (securityLevel == QKeychain::Job::Biometric) {
            const auto prompt = Job::tr("Authenticate to access %1").arg(service);
            [query setObject:prompt.toNSString() forKey:(__bridge NSString *)kSecUseOperationPrompt];
            [query setObject:[interface context] forKey:(__bridge NSString *)kSecUseAuthenticationContext];
        }

        CFErrorRef error = nil;
        SecAccessControlRef accessControl = nil;

        if (securityLevel == QKeychain::Job::Biometric) {
            accessControl = SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault, kSecAttrAccessibleWhenUnlocked,
                    kSecAccessControlUserPresence, &error);
        }

        OSStatus status = SecItemCopyMatching((__bridge const CFDictionaryRef)query, nil);

        if (status == errSecSuccess) {
            NSMutableDictionary *const update = [NSMutableDictionary dictionaryWithDictionary:@{
                (__bridge NSString *)kSecValueData : data.toNSData(),
            }];

            if (accessControl) {
                [update setObject:(__bridge id)accessControl
                           forKey:(__bridge NSString *)kSecAttrAccessControl];
                // Remove kSecAttrAccessible if it exists on the current item
                [update setObject:(__bridge id)kCFNull forKey:(__bridge NSString *)kSecAttrAccessible];
            } else {
                [update setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked
                           forKey:(__bridge NSString *)kSecAttrAccessible];
                // Remove kSecAttrAccessControl if it exists on the current item
                [update setObject:(__bridge id)kCFNull
                           forKey:(__bridge NSString *)kSecAttrAccessControl];
            }

            status = SecItemUpdate((__bridge const CFDictionaryRef)query,
                                   (__bridge const CFDictionaryRef)update);
        } else if (status == errSecItemNotFound) {
            NSMutableDictionary *const insert = [NSMutableDictionary dictionaryWithDictionary:@{
                (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
                (__bridge NSString *)kSecAttrService : service.toNSString(),
                (__bridge NSString *)kSecAttrAccount : key.toNSString(),
                (__bridge NSString *)kSecValueData : data.toNSData(),
            }];

            if (accessControl) {
                [insert setObject:(__bridge id)accessControl
                           forKey:(__bridge NSString *)kSecAttrAccessControl];
            } else {
                [insert setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked
                           forKey:(__bridge NSString *)kSecAttrAccessible];
            }

            status = SecItemAdd((__bridge const CFDictionaryRef)insert, nil);
        } else {
            NSString *const descriptiveErrorString = @"Could not store data in settings";
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });

            if (accessControl) {
                CFRelease(accessControl);
            }
            if (error) {
                CFRelease(error);
            }
            return;
        }

        if (accessControl) {
            CFRelease(accessControl);
        }
        if (error) {
            CFRelease(error);
        }

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinished];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString = @"Could not store data in settings";

            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }
    });
}

static void StartDeletePassword(const QString &service, const QString &key,
                                AppleKeychainInterface *const interface)
{
    const auto securityLevel = [interface effectiveSecurityLevel];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSMutableDictionary *const query = [NSMutableDictionary dictionaryWithDictionary:@{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecAttrAccount : key.toNSString(),
        }];

        if (securityLevel == QKeychain::Job::Biometric) {
            const auto prompt = Job::tr("Authenticate to access %1").arg(service);
            [query setObject:prompt.toNSString() forKey:(__bridge NSString *)kSecUseOperationPrompt];
            [query setObject:[interface context] forKey:(__bridge NSString *)kSecUseAuthenticationContext];
        }

        const OSStatus status = SecItemDelete((__bridge const CFDictionaryRef)query);

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinished];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString = @"Could not remove private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }
    });
}

void ReadPasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartReadPassword(service, key, interface);
}

void WritePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartWritePassword(service, key, data, interface);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartDeletePassword(service, key, interface);
}

bool QKeychain::isAvailable()
{
    return true;
}
