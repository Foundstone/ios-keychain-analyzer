//
//  FS_KA_Helper.h
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/13/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/SecBase.h>

@interface FS_KA_Helper : NSObject
{
    
}

# pragma mark Common Security Attributes
+ (NSString*)getAccessiblityForSecItem:             (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getAccessGroupForSecItem:              (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCreationDateForSecItem:             (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getModificationDateForSecItem:         (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getDescriptionForSecItem:              (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCommentForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCreatorForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getTypeForSecItem:                     (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getLabelForSecItem:                    (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getIsInvisibleForSecItem:              (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getIsNegativeForSecItem:               (NSDictionary *     )dictSecItemAttributes;

# pragma mark - Generic Password Security Attributes
+ (NSString*)getAccountForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getServiceForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getGenericForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getPasswordForSecItem:                 (NSDictionary *     )dictSecItemAttributes;

# pragma mark Internet Password Security Attributes
+ (NSString*)getSecurityDomainForSecItem:           (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getServerForSecItem:                   (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getProtocolForSecItem:                 (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getAuthenticationTypeForSecItem:       (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getPortForSecItem:                     (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getPathForSecItem:                     (NSDictionary *     )dictSecItemAttributes;

#pragma mark Certificate Attributes
+ (NSString*)getCertificateTypeForSecItem:          (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCertificateEncodingForSecItem:      (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getSubjectForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getIssuerForSecItem:                   (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getSerialNumberForSecItem:             (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getSubjectKeyIdForSecItem:             (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getPublicKeyHashForSecItem:            (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getSummaryForCert:                     (SecCertificateRef  )certRef;

#pragma mark Key Attributes
+ (NSString*)getKeyClassForSecItem:                 (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getApplicationLabelForSecItem:         (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getIsPermanentForSecItem:              (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getApplicationTagForSecItem:           (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getKeyTypeForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getKeySizeInBitsForSecItem:            (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getEffectiveKeySizeForSecItem:         (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanEncryptForSecItem:               (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanDecryptForSecItem:               (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanDeriveForSecItem:                (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanSignForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanVerifyForSecItem:                (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanWrapForSecItem:                  (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getCanUnwrapForSecItem:                (NSDictionary *     )dictSecItemAttributes;
+ (NSString*)getKeyValueForSecItem:                 (NSDictionary *     )dictSecItemAttributes;

# pragma mark Helper Functions
+ (NSString*)getStringAttributeValue:               (CFStringRef        )cfValue;
+ (NSString*)getBooleanAttributeValue:              (CFBooleanRef       )cfValue;
+ (NSString*)getDataAttributeValue:                 (CFDataRef          )cfValue;
+ (NSString*)getUTF8DataAttributeForSecItem:        (CFDataRef          )cfValue;
+ (NSString*)getNumberAttributeValue:               (CFNumberRef        )cfValue;
+ (NSString*)getDateAttributeValue:                 (CFDateRef          )cfValue;

#pragma mark JSON Serialization Function
+ (NSString*)convertDictionaryToJSON:               (NSDictionary *     )dataDict;
+ (NSString*)wrapJSONData:                          (NSString *         )strJSON
             withFunction:                          (NSString *         )strFunction;
+ (void)     saveData:                              (NSString *         )strData
               toFile:                              (NSURL *            )urlFile;

#pragma mark Analysis - Check for weak passwords
+ (BOOL)    checkIfPasswordIsWeak:                  (NSString *         )strPassword;

#pragma mark Analysis - Check for weak authentication scheme
+ (BOOL)    checkIfAuthenticationSchemeIsWeak:      (NSString *         )strAuthScheme;

#pragma mark Analysis - Check for weak protocol
+ (BOOL)    checkIfProtocolIsWeak:                  (NSString *         )strProtocol;
+ (BOOL)    checkIfInsecurePortIsBeingUsed:         (NSString *         )strPort;

#pragma mark Analysis - Check for weak key
+ (BOOL)    checkIfKeyIsWeak:                       (NSDictionary *     )dictCurrentSecItem;

#pragma mark Analysis - Check for weak accessibility
+ (BOOL)    checkIfAccessibilityIsWeak:             (NSString *         )strAccessibility;

#pragma mark File Copy
+ (void)copyItemAtURL:                              (NSURL*             )srcURL
           toDirAtURL:                              (NSURL*             )destDir;

@end
