//
//  FS_KA_Helper.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/13/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <Security/SecBase.h>
#import <Security/SecCertificate.h>

#import "FS_KA_Helper.h"
#import "FS_KA_Constants.h"

@implementation FS_KA_Helper


static NSDictionary *sProtocolDict                      = nil;
static NSDictionary *sAuthTypeDict                      = nil;
static NSDictionary *sKnownCertificateTypeDict          = nil;
static NSDictionary *sKnownCertificateEncodingsDict     = nil;
static NSDictionary *sKeyClassDict                      = nil;
static NSDictionary *sKeyTypeDict                       = nil;

static NSArray      *sWeakAuthItems                     = nil;
static NSArray      *sWeakProtocols                     = nil;
static NSArray      *sInsecurePorts                     = nil;

# pragma mark Common Security Attributes
+ (NSString*)getAccessiblityForSecItem:(NSDictionary *)dictSecItemAttributes
{
    NSString *strAccessible = @"[Not Set]";
    
    CFTypeRef cfAccessible = (__bridge CFTypeRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrAccessible)]);
    if (nil != cfAccessible) {
        if ( true == CFEqual(cfAccessible, kSecAttrAccessibleAfterFirstUnlock))
            strAccessible = kstrAccessibleAfterFirstUnlock;
        else if (true == CFEqual(cfAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly))
            strAccessible = kstrAccessibleAfterFirstUnlockDevice;
        else if (true == CFEqual(cfAccessible, kSecAttrAccessibleAlways))
            strAccessible = kstrAccessibleAlways;
        else if (true == CFEqual(cfAccessible, kSecAttrAccessibleAlwaysThisDeviceOnly))
            strAccessible =kstrAccessibleAlwaysDeviceOnly;
        else if (true == CFEqual(cfAccessible, kSecAttrAccessibleWhenUnlocked))
            strAccessible = kstrAccessibleOnUnlock;
        else if (true == CFEqual(cfAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly))
            strAccessible = kstrAccessibleOnUnlockDeviceOnly;
        else
            strAccessible = (__bridge NSString *)(cfAccessible);
    }
    
    return strAccessible;
}


+ (NSString*)getAccessGroupForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrAccessGroup)])];
}

+ (NSString*)getCreationDateForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDateAttributeValue:(__bridge CFDateRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrCreationDate)])];
}

+ (NSString*)getModificationDateForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDateAttributeValue:(__bridge CFDateRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrModificationDate)])];
}

+ (NSString*)getDescriptionForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrDescription)])];
}

+ (NSString*)getCommentForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrComment)])];
}

+ (NSString*)getCreatorForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getNumberAttributeValue:(__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrCreator)])];
}

+ (NSString*)getTypeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getNumberAttributeValue:(__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrType)])];
}

+ (NSString*)getLabelForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrLabel)])];
}

+ (NSString*)getIsInvisibleForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrIsInvisible)])];
}

+ (NSString*)getIsNegativeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrIsNegative)])];
}


# pragma mark - Generic Password Security Attributes

+ (NSString*)getAccountForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrAccount)])];
}

+ (NSString*)getServiceForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrService)])];
}

+ (NSString*)getGenericForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrGeneric)])];
}

+ (NSString*)getPasswordForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getUTF8DataAttributeForSecItem:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecValueData)])];
}


# pragma mark Internet Password Security Attributes
+ (NSString*)getSecurityDomainForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrSecurityDomain)])];
}

+ (NSString*)getServerForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrServer)])];
}

+ (NSString*)getProtocolForSecItem:(NSDictionary *)dictSecItemAttributes
{
    if (nil == sProtocolDict)
    {
        sProtocolDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                    kstrProtocolFTP,        kSecAttrProtocolFTP,
                                    kstrProtocolFTPClient,  kSecAttrProtocolFTPAccount,
                                    kstrProtocolHTTP,       kSecAttrProtocolHTTP,
                                    kstrProtocolIRC,        kSecAttrProtocolIRC,
                                    kstrProtocolNNTP,       kSecAttrProtocolNNTP,
                                    kstrProtocolPOP3,       kSecAttrProtocolPOP3,
                                    kstrProtocolSMTP,       kSecAttrProtocolSMTP,
                                    kstrProtocolSOCKS,      kSecAttrProtocolSOCKS,
                                    kstrProtocolIMAP,       kSecAttrProtocolIMAP,
                                    kstrProtocolLDAP,       kSecAttrProtocolLDAP,
                                    kstrProtocolAppleTalk,  kSecAttrProtocolAppleTalk,
                                    kstrProtocolAFP,        kSecAttrProtocolAFP,
                                    kstrProtocolTelnet,     kSecAttrProtocolTelnet,
                                    kstrProtocolSSH,        kSecAttrProtocolSSH,
                                    kstrProtocolFTPS,       kSecAttrProtocolFTPS,
                                    kstrProtocolHTTPS,      kSecAttrProtocolHTTPS,
                                    kstrProtocolFTPProxy,   kSecAttrProtocolFTPProxy,
                                    kstrProtocolHTTPProxy,  kSecAttrProtocolHTTPProxy,
                                    kstrProtocolHTTPSProxy, kSecAttrProtocolHTTPSProxy,
                                    kstrProtocolSMB,        kSecAttrProtocolSMB,
                                    kstrProtocolRTSP,       kSecAttrProtocolRTSP,
                                    kstrProtocolRTSPProxy,  kSecAttrProtocolRTSPProxy,
                                    kstrProtocolDAAP,       kSecAttrProtocolDAAP,
                                    kstrProtocolEPPC,       kSecAttrProtocolEPPC,
                                    kstrProtocolIPP,        kSecAttrProtocolIPP,
                                    kstrProtocolNTTPS,      kSecAttrProtocolNNTPS,
                                    kstrProtocolLDAPS,      kSecAttrProtocolLDAPS,
                                    kstrProtocolTelnetS,    kSecAttrProtocolTelnetS,
                                    kstrProtocolIMAPS,      kSecAttrProtocolIMAPS,
                                    kstrProtocolIRCS,       kSecAttrProtocolIRCS,
                                    kstrProtocolPOP3S,      kSecAttrProtocolPOP3S,
                                    nil];
    }
    
    NSString *strProtocol = @"[Not Set]";
    
    CFNumberRef cfProtocol = (__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrProtocol)]); //@"ptcl"
    if (nil != cfProtocol)
    {
        strProtocol = [sProtocolDict objectForKey:(__bridge id)((CFTypeRef)cfProtocol)];
        if (nil == strProtocol)
            strProtocol = [(__bridge NSNumber*)(cfProtocol) stringValue];
    }
    
    return strProtocol;
}

+ (NSString*)getAuthenticationTypeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    if (nil == sAuthTypeDict)
    {
        sAuthTypeDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                        kstrAuthTypeNTLM,       kSecAttrAuthenticationTypeNTLM,
                                        kstrAuthTypeMSN,        kSecAttrAuthenticationTypeMSN,
                                        kstrAuthTypeDPA,        kSecAttrAuthenticationTypeDPA,
                                        kstrAuthTypeRPA,        kSecAttrAuthenticationTypeRPA,
                                        kstrAuthTypeHTTPBasic,  kSecAttrAuthenticationTypeHTTPBasic,
                                        kstrAuthTypeHTTPDigest, kSecAttrAuthenticationTypeHTTPDigest,
                                        kstrAuthTypeHTTPForm,   kSecAttrAuthenticationTypeHTMLForm,
                                        kstrAuthTypeDefault,    kSecAttrAuthenticationTypeDefault,
                                        nil];
    }

    NSString* strAuthType = @"[Not Set]";
    
    CFNumberRef cfAuthType = (__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrAuthenticationType)]);   //@"atyp"
    if( nil != cfAuthType)
    {
        strAuthType = [sAuthTypeDict objectForKey:(__bridge id)((__bridge CFTypeRef)CFBridgingRelease(cfAuthType))];
        if (nil == strAuthType)
            strAuthType = [ (__bridge NSNumber*)(cfAuthType) stringValue];
    }
    
    return strAuthType;
}

+ (NSString*)getPortForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getNumberAttributeValue:(__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrPort)])];
}

+ (NSString*)getPathForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrPath)])];
}


#pragma mark Certificate Attributes
+ (NSString*)getCertificateTypeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    // The certificate types are defined in the cssmtype.h header file (See the documentation for kSecAttrCertificateType at -
    // https://developer.apple.com/library/ios/#documentation/Security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/c_ref/SecItemAdd)
    // This header file (cssmtype.h) is not present in the iOS 5.1 sdk. The following is an extract from the
    // same header file (for Mac OSX 10.7) which defines the various certificate types
    //
    //    CSSM_CERT_UNKNOWN =					0x00,
    //    CSSM_CERT_X_509v1 =					0x01,
    //    CSSM_CERT_X_509v2 =					0x02,
    //    CSSM_CERT_X_509v3 =					0x03,
    //    CSSM_CERT_PGP =						0x04,
    //    CSSM_CERT_SPKI =					0x05,
    //    CSSM_CERT_SDSIv1 =					0x06,
    //    CSSM_CERT_Intel =					0x08,
    //    CSSM_CERT_X_509_ATTRIBUTE =			0x09, /* X.509 attribute cert */
    //    CSSM_CERT_X9_ATTRIBUTE =			0x0A, /* X9 attribute cert */
    //    CSSM_CERT_TUPLE =					0x0B,
    //    CSSM_CERT_ACL_ENTRY =				0x0C,
    //    CSSM_CERT_MULTIPLE =				0x7FFE,
    //    CSSM_CERT_LAST =					0x7FFF,
    //	/* Applications wishing to define their own custom certificate
    //     type should define and publicly document a uint32 value greater
    //     than the CSSM_CL_CUSTOM_CERT_TYPE */
    //	CSSM_CL_CUSTOM_CERT_TYPE =			0x08000
    //
    
    if (nil == sKnownCertificateTypeDict)
    {
        sKnownCertificateTypeDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                                kstrCertTypeUnknown,    [NSNumber numberWithUnsignedLong:0x00],
                                                kstrCertTypeX509V1,     [NSNumber numberWithUnsignedLong:0x01],
                                                kstrCertTypeX509V2,     [NSNumber numberWithUnsignedLong:0x02],
                                                kstrCertTypeX509V3,     [NSNumber numberWithUnsignedLong:0x03],
                                                kstrCertTypePGP,        [NSNumber numberWithUnsignedLong:0x04],
                                                kstrCertTypeSPKI,       [NSNumber numberWithUnsignedLong:0x05],
                                                kstrCertTypeSDSIV1,     [NSNumber numberWithUnsignedLong:0x06],
                                                kstrCertTypeIntel,      [NSNumber numberWithUnsignedLong:0x08],
                                                kstrCertTypeIntel,      [NSNumber numberWithUnsignedLong:0x09],
                                                kstrCertTypeX9,         [NSNumber numberWithUnsignedLong:0x0A],
                                                kstrCertTypeTuple,      [NSNumber numberWithUnsignedLong:0x0B],
                                                kstrCertTypeACLEntry,   [NSNumber numberWithUnsignedLong:0x0C],
                                                kstrCertTypeMultiple,   [NSNumber numberWithUnsignedLong:0x7FFE],
                                                kstrCertTypeLast,       [NSNumber numberWithUnsignedLong:0x7FFF],
                                                nil];
    }
    
    NSString *strCertificateType = @"[Not Set]";
    NSNumber *nsCertificateType = [dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrCertificateType)]; //@"ctyp"
    if (nil != nsCertificateType)
    {
        strCertificateType = [sKnownCertificateTypeDict objectForKey:nsCertificateType];
        if (nil == strCertificateType)
        {
            if (NSOrderedAscending != [nsCertificateType compare:[NSNumber numberWithUnsignedLong:0x08000]])
            {
                //Certificate Type >= 0x08000
                strCertificateType = @"Custom";
            }
        }
    }
    
    return strCertificateType;
}

+ (NSString*)getCertificateEncodingForSecItem:(NSDictionary *)dictSecItemAttributes
{
    //     The certificate encodings are defined in the cssmtype.h header file (See the documentation for kSecAttrCertificateEncoding at -
    //     https://developer.apple.com/library/ios/#documentation/Security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/c_ref/SecItemAdd)
    //     This header file (cssmtype.h) is not present in the iOS 5.1 sdk. The following is an extract from the
    //     same header file (for Mac OSX 10.7) which defines the various certificate types
    //
    //        CSSM_CERT_ENCODING_UNKNOWN =		0x00,
    //        CSSM_CERT_ENCODING_CUSTOM =		0x01,
    //        CSSM_CERT_ENCODING_BER =			0x02,
    //        CSSM_CERT_ENCODING_DER =			0x03,
    //        CSSM_CERT_ENCODING_NDR =			0x04,
    //        CSSM_CERT_ENCODING_SEXPR =		0x05,
    //        CSSM_CERT_ENCODING_PGP =			0x06,
    //        CSSM_CERT_ENCODING_MULTIPLE =		0x7FFE,
    //        CSSM_CERT_ENCODING_LAST =			0x7FFF,
    //        /* Applications wishing to define their own custom certificate
    //         encoding should create a uint32 value greater than the
    //         CSSM_CL_CUSTOM_CERT_ENCODING */
    //        CSSM_CL_CUSTOM_CERT_ENCODING =		0x8000
    //
    //
    
    if (nil == sKnownCertificateEncodingsDict)
    {
        sKnownCertificateEncodingsDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                          kstrCertEncodingUnkown,       [NSNumber numberWithUnsignedLong:0x00],
                                          kstrCertEncodingCustom,       [NSNumber numberWithUnsignedLong:0x01],
                                          kstrCertEncodingBER,          [NSNumber numberWithUnsignedLong:0x02],
                                          kstrCertEncodingDER,          [NSNumber numberWithUnsignedLong:0x03],
                                          kstrCertEncodingNDR,          [NSNumber numberWithUnsignedLong:0x04],
                                          kstrCertEncodingSXPR,         [NSNumber numberWithUnsignedLong:0x05],
                                          kstrCertEncodingPGP,          [NSNumber numberWithUnsignedLong:0x06],
                                          kstrCertEncodingMultiple,     [NSNumber numberWithUnsignedLong:0x7FFE],
                                          kstrCertEncodingLast,         [NSNumber numberWithUnsignedLong:0x7FFF],
                                          nil];
    }
    
    NSString *strCertificateEncoding = @"[Not Set]";
    
    NSNumber *nsCertificateEncoding = [dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrCertificateEncoding)]; //@"cenc"
    if (nil != nsCertificateEncoding)
    {
        strCertificateEncoding = [sKnownCertificateEncodingsDict objectForKey:nsCertificateEncoding];
        if (nil == strCertificateEncoding)
        {
            if (NSOrderedAscending != [nsCertificateEncoding compare:[NSNumber numberWithUnsignedLong:0x8000]])
            {
                //Certificate Encoding >= 0x8000
                strCertificateEncoding = @"Custom";
            }
            else
            {
                strCertificateEncoding = @"[Unknown]";
            }
        }
    }
    
    return strCertificateEncoding;
}

+ (NSString*)getSubjectForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrSubject)])];
}

+ (NSString*)getIssuerForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrIssuer)])];
}

+ (NSString*)getSerialNumberForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrSerialNumber)])];
}

+ (NSString*)getSubjectKeyIdForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrSubjectKeyID)])];
}

+ (NSString*)getPublicKeyHashForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getDataAttributeValue:(__bridge CFDataRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrPublicKeyHash)])];
}

+ (NSString*)getSummaryForCert:(SecCertificateRef)certRef
{
    NSString *strRetValue = @"[Not Set]";
    
    if (NULL != certRef)
    {
        CFStringRef cfstrSummary = (SecCertificateCopySubjectSummary(certRef));
        strRetValue = [self getStringAttributeValue:cfstrSummary];
    }
    
    return strRetValue;
}

#pragma mark Key Attributes
+ (NSString*)getKeyClassForSecItem:(NSDictionary *)dictSecItemAttributes
{
    NSString *strKeyClass = @"[Not Set]";

    if (nil == sKeyClassDict)
    {
        //kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic, kSecAttrKeyClassSymmetric are defined as strings
        sKeyClassDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                        kstrKeyClassPrivate,         kSecAttrKeyClassPrivate,
                                        kstrKeyClassPublic,          kSecAttrKeyClassPublic,
                                        kstrKeyClassSymmetric,       kSecAttrKeyClassSymmetric,
                                        nil];
    }
    
    //The value for kSecAttrKeyClass attribute is a number/integer data type
    NSNumber *nsKeyClass =[dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrKeyClass)];
    if (nil != nsKeyClass)
    {
        NSString *nsStringKeyClass = [nsKeyClass stringValue];
        strKeyClass = [sKeyClassDict objectForKey:nsStringKeyClass];
        if (nil == strKeyClass)
            strKeyClass = @"[Unknown]";
    }
    
    return strKeyClass;
}

+ (NSString*)getApplicationLabelForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getStringAttributeValue:(__bridge CFStringRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrApplicationLabel)])];
}

+ (NSString*)getIsPermanentForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrIsPermanent)])];
}

+ (NSString*)getApplicationTagForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getUTF8DataAttributeForSecItem:(__bridge CFDataRef)[dictSecItemAttributes objectForKey:(__bridge id)kSecAttrApplicationTag]];
}

+ (NSString*)getKeyTypeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    //     The key types encodings are defined in the cssmtype.h and cssmapple.h header files (See the documentation for kSecAttrKeyType at -
    //     https://developer.apple.com/library/ios/#documentation/Security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/c_ref/SecItemAdd)
    //     These header files (cssmtype.h and cssmapple.h) is not present in the iOS 5.1 sdk. The following is an extract from the
    //     same header files (for Mac OSX 10.7) which defines the various key types (CSSM_ALGORITHMS enumeration)
    //
    
    if (nil == sKeyTypeDict)
    {
        sKeyTypeDict = [NSDictionary dictionaryWithObjectsAndKeys:
                        @"CSSM_ALGID_NONE", [NSNumber numberWithUnsignedLong:0],
                        @"CSSM_ALGID_CUSTOM", [NSNumber numberWithUnsignedLong:1],
                        @"CSSM_ALGID_DH", [NSNumber numberWithUnsignedLong:2],
                        @"CSSM_ALGID_PH", [NSNumber numberWithUnsignedLong:3],
                        @"CSSM_ALGID_KEA", [NSNumber numberWithUnsignedLong:4],
                        @"CSSM_ALGID_MD2", [NSNumber numberWithUnsignedLong:5],
                        @"CSSM_ALGID_MD4", [NSNumber numberWithUnsignedLong:6],
                        @"CSSM_ALGID_MD5", [NSNumber numberWithUnsignedLong:7],
                        @"CSSM_ALGID_SHA1", [NSNumber numberWithUnsignedLong:8],
                        @"CSSM_ALGID_NHASH", [NSNumber numberWithUnsignedLong:9],
                        @"CSSM_ALGID_HAVAL", [NSNumber numberWithUnsignedLong:10],
                        @"CSSM_ALGID_RIPEMD", [NSNumber numberWithUnsignedLong:11],
                        @"CSSM_ALGID_IBCHASH", [NSNumber numberWithUnsignedLong:12],
                        @"CSSM_ALGID_RIPEMAC", [NSNumber numberWithUnsignedLong:13],
                        @"CSSM_ALGID_DES", [NSNumber numberWithUnsignedLong:14],
                        @"CSSM_ALGID_DESX", [NSNumber numberWithUnsignedLong:15],
                        @"CSSM_ALGID_RDES", [NSNumber numberWithUnsignedLong:16],
                        @"CSSM_ALGID_3DES_3KEY_EDE", [NSNumber numberWithUnsignedLong:17],
                        @"CSSM_ALGID_3DES_2KEY_EDE", [NSNumber numberWithUnsignedLong:18],
                        @"CSSM_ALGID_3DES_1KEY_EEE", [NSNumber numberWithUnsignedLong:19],
                        @"CSSM_ALGID_3DES_3KEY_EEE", [NSNumber numberWithUnsignedLong:20],
                        @"CSSM_ALGID_3DES_2KEY_EEE", [NSNumber numberWithUnsignedLong:21],
                        @"CSSM_ALGID_IDEA", [NSNumber numberWithUnsignedLong:22],
                        @"CSSM_ALGID_RC2", [NSNumber numberWithUnsignedLong:23],
                        @"CSSM_ALGID_RC5", [NSNumber numberWithUnsignedLong:24],
                        @"CSSM_ALGID_RC4", [NSNumber numberWithUnsignedLong:25],
                        @"CSSM_ALGID_SEAL", [NSNumber numberWithUnsignedLong:26],
                        @"CSSM_ALGID_CAST", [NSNumber numberWithUnsignedLong:27],
                        @"CSSM_ALGID_BLOWFISH", [NSNumber numberWithUnsignedLong:28],
                        @"CSSM_ALGID_SKIPJACK", [NSNumber numberWithUnsignedLong:29],
                        @"CSSM_ALGID_LUCIFER", [NSNumber numberWithUnsignedLong:30],
                        @"CSSM_ALGID_MADRYGA", [NSNumber numberWithUnsignedLong:31],
                        @"CSSM_ALGID_FEAL", [NSNumber numberWithUnsignedLong:32],
                        @"CSSM_ALGID_REDOC", [NSNumber numberWithUnsignedLong:33],
                        @"CSSM_ALGID_REDOC3", [NSNumber numberWithUnsignedLong:34],
                        @"CSSM_ALGID_LOKI", [NSNumber numberWithUnsignedLong:35],
                        @"CSSM_ALGID_KHUFU", [NSNumber numberWithUnsignedLong:36],
                        @"CSSM_ALGID_KHAFRE", [NSNumber numberWithUnsignedLong:37],
                        @"CSSM_ALGID_MMB", [NSNumber numberWithUnsignedLong:38],
                        @"CSSM_ALGID_GOST", [NSNumber numberWithUnsignedLong:39],
                        @"CSSM_ALGID_SAFER", [NSNumber numberWithUnsignedLong:40],
                        @"CSSM_ALGID_CRAB", [NSNumber numberWithUnsignedLong:41],
                        @"CSSM_ALGID_RSA", [NSNumber numberWithUnsignedLong:42],
                        @"CSSM_ALGID_DSA", [NSNumber numberWithUnsignedLong:43],
                        @"CSSM_ALGID_MD5WithRSA", [NSNumber numberWithUnsignedLong:44],
                        @"CSSM_ALGID_MD2WithRSA", [NSNumber numberWithUnsignedLong:45],
                        @"CSSM_ALGID_ElGamal", [NSNumber numberWithUnsignedLong:46],
                        @"CSSM_ALGID_MD2Random", [NSNumber numberWithUnsignedLong:47],
                        @"CSSM_ALGID_MD5Random", [NSNumber numberWithUnsignedLong:48],
                        @"CSSM_ALGID_SHARandom", [NSNumber numberWithUnsignedLong:49],
                        @"CSSM_ALGID_DESRandom", [NSNumber numberWithUnsignedLong:50],
                        @"CSSM_ALGID_SHA1WithRSA", [NSNumber numberWithUnsignedLong:51],
                        @"CSSM_ALGID_CDMF", [NSNumber numberWithUnsignedLong:52],
                        @"CSSM_ALGID_CAST3", [NSNumber numberWithUnsignedLong:53],
                        @"CSSM_ALGID_CAST5", [NSNumber numberWithUnsignedLong:54],
                        @"CSSM_ALGID_GenericSecret", [NSNumber numberWithUnsignedLong:55],
                        @"CSSM_ALGID_ConcatBaseAndKey", [NSNumber numberWithUnsignedLong:56],
                        @"CSSM_ALGID_ConcatKeyAndBase", [NSNumber numberWithUnsignedLong:57],
                        @"CSSM_ALGID_ConcatBaseAndDat", [NSNumber numberWithUnsignedLong:58],
                        @"CSSM_ALGID_ConcatDataAndBas", [NSNumber numberWithUnsignedLong:59],
                        @"CSSM_ALGID_XORBaseAndData", [NSNumber numberWithUnsignedLong:60],
                        @"CSSM_ALGID_ExtractFromKey", [NSNumber numberWithUnsignedLong:61],
                        @"CSSM_ALGID_SSL3PreMasterGen", [NSNumber numberWithUnsignedLong:62],
                        @"CSSM_ALGID_SSL3MasterDerive", [NSNumber numberWithUnsignedLong:63],
                        @"CSSM_ALGID_SSL3KeyAndMacDer", [NSNumber numberWithUnsignedLong:64],
                        @"CSSM_ALGID_SSL3MD5_MAC", [NSNumber numberWithUnsignedLong:65],
                        @"CSSM_ALGID_SSL3SHA1_MAC", [NSNumber numberWithUnsignedLong:66],
                        @"CSSM_ALGID_PKCS5_PBKDF1_MD5", [NSNumber numberWithUnsignedLong:67],
                        @"CSSM_ALGID_PKCS5_PBKDF1_MD2", [NSNumber numberWithUnsignedLong:68],
                        @"CSSM_ALGID_PKCS5_PBKDF1_SHA", [NSNumber numberWithUnsignedLong:69],
                        @"CSSM_ALGID_WrapLynks", [NSNumber numberWithUnsignedLong:70],
                        @"CSSM_ALGID_WrapSET_OAEP", [NSNumber numberWithUnsignedLong:71],
                        @"CSSM_ALGID_BATON", [NSNumber numberWithUnsignedLong:72],
                        @"CSSM_ALGID_ECDSA", [NSNumber numberWithUnsignedLong:73],
                        @"CSSM_ALGID_MAYFLY", [NSNumber numberWithUnsignedLong:74],
                        @"CSSM_ALGID_JUNIPER", [NSNumber numberWithUnsignedLong:75],
                        @"CSSM_ALGID_FASTHASH", [NSNumber numberWithUnsignedLong:76],
                        @"CSSM_ALGID_3DES", [NSNumber numberWithUnsignedLong:77],
                        @"CSSM_ALGID_SSL3MD5", [NSNumber numberWithUnsignedLong:78],
                        @"CSSM_ALGID_SSL3SHA1", [NSNumber numberWithUnsignedLong:79],
                        @"CSSM_ALGID_FortezzaTimestam", [NSNumber numberWithUnsignedLong:80],
                        @"CSSM_ALGID_SHA1WithDSA", [NSNumber numberWithUnsignedLong:81],
                        @"CSSM_ALGID_SHA1WithECDSA", [NSNumber numberWithUnsignedLong:82],
                        @"CSSM_ALGID_DSA_BSAFE", [NSNumber numberWithUnsignedLong:83],
                        @"CSSM_ALGID_ECDH", [NSNumber numberWithUnsignedLong:84],
                        @"CSSM_ALGID_ECMQV", [NSNumber numberWithUnsignedLong:85],
                        @"CSSM_ALGID_PKCS12_SHA1_PBE", [NSNumber numberWithUnsignedLong:86],
                        @"CSSM_ALGID_ECNRA", [NSNumber numberWithUnsignedLong:87],
                        @"CSSM_ALGID_SHA1WithECNRA", [NSNumber numberWithUnsignedLong:88],
                        @"CSSM_ALGID_ECES", [NSNumber numberWithUnsignedLong:89],
                        @"CSSM_ALGID_ECAES", [NSNumber numberWithUnsignedLong:90],
                        @"CSSM_ALGID_SHA1HMAC", [NSNumber numberWithUnsignedLong:91],
                        @"CSSM_ALGID_FIPS186Random", [NSNumber numberWithUnsignedLong:92],
                        @"CSSM_ALGID_ECC", [NSNumber numberWithUnsignedLong:93],
                        @"CSSM_ALGID_MQV", [NSNumber numberWithUnsignedLong:94],
                        @"CSSM_ALGID_NRA", [NSNumber numberWithUnsignedLong:95],
                        @"CSSM_ALGID_IntelPlatformRan", [NSNumber numberWithUnsignedLong:96],
                        @"CSSM_ALGID_UTC", [NSNumber numberWithUnsignedLong:97],
                        @"CSSM_ALGID_HAVAL3", [NSNumber numberWithUnsignedLong:98],
                        @"CSSM_ALGID_HAVAL4", [NSNumber numberWithUnsignedLong:99],
                        @"CSSM_ALGID_HAVAL5", [NSNumber numberWithUnsignedLong:100],
                        @"CSSM_ALGID_TIGER", [NSNumber numberWithUnsignedLong:101],
                        @"CSSM_ALGID_MD5HMAC", [NSNumber numberWithUnsignedLong:102],
                        @"CSSM_ALGID_PKCS5_PBKDF2", [NSNumber numberWithUnsignedLong:103],
                        @"CSSM_ALGID_RUNNING_COUNTER", [NSNumber numberWithUnsignedLong:104],
                        @"CSSM_ALGID_LAST", [NSNumber numberWithUnsignedLong:0x7FFFFFFF],
                        @"CSSM_ALGID_APPLE_YARROW", [NSNumber numberWithUnsignedLong:0x80000000],
                        @"CSSM_ALGID_AES", [NSNumber numberWithUnsignedLong:0x80000001],
                        @"CSSM_ALGID_FEE", [NSNumber numberWithUnsignedLong:0x80000002],
                        @"CSSM_ALGID_FEE_MD5", [NSNumber numberWithUnsignedLong:0x80000003],
                        @"CSSM_ALGID_FEE_SHA1", [NSNumber numberWithUnsignedLong:0x80000004],
                        @"CSSM_ALGID_FEED", [NSNumber numberWithUnsignedLong:0x80000005],
                        @"CSSM_ALGID_FEEDEXP", [NSNumber numberWithUnsignedLong:0x80000006],
                        @"CSSM_ALGID_ASC", [NSNumber numberWithUnsignedLong:0x80000007],
                        @"CSSM_ALGID_SHA1HMAC_LEGACY", [NSNumber numberWithUnsignedLong:0x80000008],
                        @"CSSM_ALGID_KEYCHAIN_KEY", [NSNumber numberWithUnsignedLong:0x80000009],
                        @"CSSM_ALGID_PKCS12_PBE_ENCR", [NSNumber numberWithUnsignedLong:0x8000000A],
                        @"CSSM_ALGID_PKCS12_PBE_MAC", [NSNumber numberWithUnsignedLong:0x8000000B],
                        @"CSSM_ALGID_SECURE_PASSPHRASE", [NSNumber numberWithUnsignedLong:0x8000000C],
                        @"CSSM_ALGID_PBE_OPENSSL_MD5 ", [NSNumber numberWithUnsignedLong:0x8000000D],
                        @"CSSM_ALGID_SHA256", [NSNumber numberWithUnsignedLong:0x8000000E],
                        @"CSSM_ALGID_SHA384", [NSNumber numberWithUnsignedLong:0x8000000F],
                        @"CSSM_ALGID_SHA512", [NSNumber numberWithUnsignedLong:0x80000010],
                        @"CSSM_ALGID_ENTROPY_DEFAULT", [NSNumber numberWithUnsignedLong:0x80000011],
                        @"CSSM_ALGID_SHA224", [NSNumber numberWithUnsignedLong:0x80000012],
                        @"CSSM_ALGID_SHA224WithRSA", [NSNumber numberWithUnsignedLong:0x80000013],
                        @"CSSM_ALGID_SHA256WithRSA", [NSNumber numberWithUnsignedLong:0x80000014],
                        @"CSSM_ALGID_SHA384WithRSA", [NSNumber numberWithUnsignedLong:0x80000015],
                        @"CSSM_ALGID_SHA512WithRSA", [NSNumber numberWithUnsignedLong:0x80000016],
                        @"CSSM_ALGID_OPENSSH1", [NSNumber numberWithUnsignedLong:0x80000017],
                        @"CSSM_ALGID_SHA224WithECDSA", [NSNumber numberWithUnsignedLong:0x80000018],
                        @"CSSM_ALGID_SHA256WithECDSA", [NSNumber numberWithUnsignedLong:0x80000019],
                        @"CSSM_ALGID_SHA384WithECDSA", [NSNumber numberWithUnsignedLong:0x8000001A],
                        @"CSSM_ALGID_SHA512WithECDSA", [NSNumber numberWithUnsignedLong:0x8000001B],
                        @"CSSM_ALGID_ECDSA_SPECIFIED", [NSNumber numberWithUnsignedLong:0x8000001C],
                        @"CSSM_ALGID_ECDH_X963_KDF", [NSNumber numberWithUnsignedLong:0x8000001D],
                        @"CSSM_ALGID__FIRST_UNUSED", [NSNumber numberWithUnsignedLong:0x8000001E],
                        nil];
    }
    
    NSString* strKeyType = @"[Not Set]";
    
    NSNumber *nsKeyType = [dictSecItemAttributes objectForKey:(__bridge id)(kSecAttrKeyType)];
    if( nil != nsKeyType)
    {
        strKeyType = [sKeyTypeDict objectForKey:nsKeyType];
        if (nil == strKeyType)
        {
            if (NSOrderedAscending != [nsKeyType compare:[NSNumber numberWithUnsignedLong:0x80000000]])
            {
                //Certificate Encoding >= 0x80000000
                strKeyType = @"Vendor Defined";
            }
            else
            {
                strKeyType = [nsKeyType stringValue];
            }
            
        }
    }
    
    return strKeyType;
}

+ (NSString*)getKeySizeInBitsForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getNumberAttributeValue:(__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrKeySizeInBits])];
}

+ (NSString*)getEffectiveKeySizeForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getNumberAttributeValue:(__bridge CFNumberRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrEffectiveKeySize])];
}

+ (NSString*)getCanEncryptForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanEncrypt])];
}

+ (NSString*)getCanDecryptForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanDecrypt])];
}

+ (NSString*)getCanDeriveForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanDerive])];
}

+ (NSString*)getCanSignForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanSign])];
}

+ (NSString*)getCanVerifyForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanVerify])];
}

+ (NSString*)getCanWrapForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanWrap])];
}

+ (NSString*)getCanUnwrapForSecItem:(NSDictionary *)dictSecItemAttributes
{
    return [self getBooleanAttributeValue:(__bridge CFBooleanRef)([dictSecItemAttributes objectForKey:(__bridge id)kSecAttrCanUnwrap])];
}

+ (NSString*)getKeyValueForSecItem:(NSDictionary *)dictSecItemAttributes
{
    NSString* strKeyClass = [self getKeyClassForSecItem:dictSecItemAttributes];
    
    if ( NSOrderedSame != [strKeyClass compare:kstrKeyClassSymmetric])
    {
        //We do not have the actual public - private key bytes. We have the opaque public/private key structure but not the actual bytes
        return @"[Cannot be displayed]";
    }
 
    return [self getDataAttributeValue:(__bridge CFDataRef)[dictSecItemAttributes objectForKey:(__bridge id)kSecValueData]];
}


# pragma mark Helper Functions
+ (NSString*)getStringAttributeValue:(CFStringRef) cfValue
{
    NSString *strRetValue = (__bridge NSString *)(cfValue);
    
    if (nil == strRetValue)
    {
        strRetValue = @"[Not Set]";
        return strRetValue;
    }
    
    if([strRetValue isKindOfClass:[NSData class]])
    {
        //This really should not happen. However, at times we get an NSData returned for CFString type which is a problem
        //since the json serializer fails if there is a NSData object in our array or dictionary
        NSString *strRetVal2 = [(NSData*)(strRetValue) description];
        if(0 == [strRetVal2 length])
            strRetVal2 = @"[Empty]";
        
        return  strRetVal2;
    }
    
    if(0 == [strRetValue length])
        strRetValue = @"[Empty]";
    
    return strRetValue;
}


+ (NSString*)getBooleanAttributeValue:(CFBooleanRef)cfValue
{
    NSString *strRetValue = @"[Not Set]";
    if (NULL != cfValue)
    {
        if (true == CFBooleanGetValue(cfValue))
            strRetValue = @"Yes";
        else
            strRetValue = @"No";
    }
    
    return strRetValue;
}

+ (NSString*)getDataAttributeValue:(CFDataRef) cfValue
{
    NSString *strRetValue = @"[Not Set]";
    
    NSData *nsValue = (__bridge NSData*) cfValue;
    if (nil != nsValue)
    {
        if (0 == [nsValue length])
        {
            strRetValue = @"[Empty]";
        }
        else
        {
            strRetValue = [nsValue description];
        }
    }
    
    return strRetValue;
}

+ (NSString*)getUTF8DataAttributeForSecItem:(CFDataRef)cfValue
{
    NSString *strValue = @"[Not Set]";
    NSData *nsValue = (__bridge NSData*)cfValue;
    
    if (nil != nsValue)
    {
        if (0 == [nsValue length])
        {
            strValue = @"[Empty]";
        }
        else
        {
            strValue = [[NSString alloc]initWithData:nsValue encoding:NSUTF8StringEncoding];
        }
    }
    
    return strValue;
}

+ (NSString*)getNumberAttributeValue:(CFNumberRef) cfValue
{
    NSString *strRetValue = @"[Not Set]";
    if (NULL != cfValue)
    {
        strRetValue = [(__bridge NSNumber*) cfValue stringValue];
    }
    
    return strRetValue;
}

+ (NSString*)getDateAttributeValue:(CFDateRef) cfValue
{
    //Creation Date
    NSDateFormatter *dtFormatter = [[NSDateFormatter alloc] init];
    [dtFormatter setTimeStyle:NSDateFormatterShortStyle];
    [dtFormatter setDateStyle:NSDateFormatterShortStyle];
    
    NSString *strRetValue = @"[Not Set]";
    
    if (NULL != cfValue)
        strRetValue = [dtFormatter stringFromDate:(__bridge NSDate*)cfValue];
    
    return strRetValue;
}


#pragma mark JSON Serialization Function
+ (NSString*)convertDictionaryToJSON:(NSDictionary*)dataDict
{
    NSError *errString;
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dataDict options:NSJSONWritingPrettyPrinted error:&errString];
    if(nil == jsonData)
    {
        NSLog(@"Ereor occured while converting data dictionary to JSON. Error message - %@", [errString description]);
        return nil;
    }
    
    NSString *strJSON = [[NSString alloc]initWithData:jsonData encoding:NSUTF8StringEncoding];
    return strJSON;
}

+ (NSString*)wrapJSONData:(NSString*)strJSON withFunction:(NSString*)strFunction
{
    //Initialize the JSON response string to 10KB size
    NSMutableString *strJSONP = [NSMutableString stringWithCapacity:1024*10];
    [strJSONP appendString:strFunction];
    [strJSONP appendString:@"(\n"];
    [strJSONP appendString:strJSON];
    [strJSONP appendString:@"\n);"];

    return strJSONP;
}

+ (void)saveData:(NSString*)strData toFile:(NSURL*)urlFile
{
    NSError* errString;
    
    BOOL bSuccess = [strData writeToURL:urlFile atomically:YES encoding:NSUTF8StringEncoding error:&errString];
    if (YES != bSuccess)
    {
        NSLog(@"Error occured while writing data to the file - %@. Error is %@", [urlFile path], [errString localizedDescription]);
    }
    
    return;
}

#pragma mark Analysis - Check for weak passwords
+ (BOOL)checkIfPasswordIsWeak:(NSString*)strPassword
{
    if (kWeakPassword_MaxLen >= [strPassword length])
        return YES;
    
    NSRange rangeAlphabetic = [strPassword rangeOfCharacterFromSet:[NSCharacterSet letterCharacterSet]];
    if (NSNotFound == rangeAlphabetic.location)
        return YES; //no alphabet is present
    
    NSRange rangeNumeric = [strPassword rangeOfCharacterFromSet:[NSCharacterSet decimalDigitCharacterSet]];
    if (NSNotFound == rangeNumeric.location)
        return YES; //no number is present
    
    NSRange rangeSpecialChar = [strPassword rangeOfCharacterFromSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]];
    if (NSNotFound == rangeSpecialChar.location)
        return YES; //no special character is present
    
    return NO; //strong password
}

#pragma mark Analysis - Check for weak authentication scheme
+ (BOOL)checkIfAuthenticationSchemeIsWeak:(NSString*)strAuthScheme
{
    if (nil == sWeakAuthItems)
    {
        sWeakAuthItems = [NSArray arrayWithObjects:
                                    kstrAuthTypeHTTPBasic,
                                    kstrAuthTypeHTTPDigest,
                          nil];
    }
    
    if (YES == [sWeakAuthItems containsObject:strAuthScheme])
    {
        return YES; //weak authentication scheme
    }
    
    return NO; //strong authentication scheme
}

#pragma mark Analysis - Check for weak protocol
+ (BOOL)checkIfProtocolIsWeak:(NSString*)strProtocol
{
    if (nil == sWeakProtocols)
    {
        sWeakProtocols = [NSArray arrayWithObjects:
                                    kstrProtocolFTP,
                                    kstrProtocolFTPClient,
                                    kstrProtocolHTTP,
                                    kstrProtocolTelnet,
                                    kstrProtocolFTPProxy,
                                    kstrProtocolHTTPProxy,
                                    kstrProtocolNNTP,
                                    kstrProtocolPOP3,
                                    kstrProtocolIMAP,
                                    kstrProtocolIRC,
                                    kstrProtocolLDAP,
                          nil];
    }

    if (YES == [sWeakProtocols containsObject:strProtocol])
    {
        return YES; //weak protocol
    }
    
    return NO; //strong protocol
}

+ (BOOL)checkIfInsecurePortIsBeingUsed:(NSString*)strPort
{
    if (nil == sInsecurePorts)
    {
        sInsecurePorts = [NSArray arrayWithObjects:
                                    kstrInsecurePortFTP,
                                    kstrInsecurePortHTTP,
                                    kstrInsecurePortTelnet,
                                    kstrInsecurePortNNTP,
                                    kstrInsecurePortPOP3,
                                    kstrInsecurePortIMAP,
                                    kstrInsecurePortIRC,
                                    kstrInsecurePortLDAP,
                          nil];
    }

    if (YES == [sInsecurePorts containsObject:strPort])
    {
        return YES; //insecure port
    }
    
    return NO; //secure port
}

#pragma mark Analysis - Check for weak key
+ (BOOL)checkIfKeyIsWeak:(NSDictionary*)dictCurrentSecItem
{
    NSString* strKeyClass   =   [dictCurrentSecItem objectForKey:kstrKey_KeyClass];
    NSString* strKeyLen     =   [dictCurrentSecItem objectForKey:kstrKey_KeySize];
    NSString* strKeyValue   =   [dictCurrentSecItem objectForKey:kstrKey_KeyValue];
    
    if (NSOrderedSame == [strKeyClass caseInsensitiveCompare:kstrKeyClassSymmetric])
    {
        //For symmetric keys, the key length could be set to any value.
        //E.g. while adding a 128 bit symmetric key to the keychain, it is possible to set the length attribute to any value.
        //Hence we rely on the actual key to determine if it is less than 128 bits or not
        if ([strKeyValue length] < kStrongSymmKey_MinLengthInHexChars)
            return YES; //Weak symmetric key length < 128 bit
    }
    else
    {
        //For public and private keys we use the key length to determine if the key is weak
        NSNumberFormatter *numberFormatter = [[NSNumberFormatter alloc] init];
        [numberFormatter setNumberStyle:NSNumberFormatterDecimalStyle];
        NSNumber* keyLenInBits = [numberFormatter numberFromString:strKeyLen];
        if (NSOrderedAscending == [keyLenInBits compare:[NSNumber numberWithUnsignedLong:kStrongAsymmKey_MinLengthInBits]])
        {
            return YES; //Weak asymmetric key len < 1024 bits
        }
    }
    return NO; //Strong key length
}

#pragma mark Analysis - Check for weak accessibility
+ (BOOL)checkIfAccessibilityIsWeak:(NSString*)strAccessibility
{
    NSRange substringSearch;
    substringSearch = [strAccessibility rangeOfString:kstrAccessibleAlways options:NSCaseInsensitiveSearch];
    if (NSNotFound != substringSearch.location)
        return YES; //Insecure
    
    return NO; //Secure
}

#pragma mark File Copy
+ (void)copyItemAtURL: (NSURL*)srcURL toDirAtURL:(NSURL*)destDir
{
    NSURL* destURL = [destDir URLByAppendingPathComponent:[srcURL lastPathComponent] isDirectory:NO];
    NSError* errString;
    BOOL bSuccess= [[NSFileManager defaultManager]copyItemAtURL:srcURL toURL:destURL error:&errString];
    if (YES != bSuccess)
    {
        //This can also happen if the file exists
        NSLog(@"Error occured while copying the file to %@. Error is %@", [destURL path], [errString localizedDescription]);
        return;
    }
    
    return;
}


@end
