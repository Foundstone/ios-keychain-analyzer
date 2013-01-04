//
//  FS_KA_Constants.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/15/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import "FS_KA_Constants.h"

@implementation FS_KA_Constants

#pragma mark Count/Initial Size Constants
const   unsigned int  kTypesOfKeychainItems                   = 5;
const   unsigned int  kNumOfAttributesPerKeychainItem         = 40;
const   unsigned int  kInitialNumOfGenericPasswords           = 5;
const   unsigned int  kInitialNumOfInternetPasswords          = 5;
const   unsigned int  kInitialNumOfCertificates               = 5;
const   unsigned int  kInitialNumOfKeys                       = 5;
const   unsigned int  kInitialNumOfIdentities                 = 5;
const   unsigned int  kNumofKeychainAnalysisChecks            = 5;
const   unsigned int  kNumOfAttributesPerAnalysisResultItem   = 40;
const   unsigned int  kInitialNumOfWeakPasswordItems          = 5;
const   unsigned int  kInitialNumOfWeakAuthenticationItems    = 5;
const   unsigned int  kInitialNumOfWeakProtocolItems          = 5;
const   unsigned int  kInitialNumOfWeakKeyItems               = 5;
const   unsigned int  kInitialNumOfWeakAccessibilityItems     = 5;

#pragma mark Keychain Data Result Dictionary Keys
NSString*   const     kstrKeyGenericPasswords                 = @"GenericPasswords";
NSString*   const     kstrKeyInternetPasswords                = @"InternetPasswords";
NSString*   const     kstrKeyCertificates                     = @"Certificates";
NSString*   const     kstrKeyKeys                             = @"Keys";
NSString*   const     kstrKeyIdentities                       = @"Identities";

#pragma mark Keychain Item Attributes
NSString*   const     kstrKeyAccessible                       = @"Accessible";
NSString*   const     kstrKeyAccessGroup                      = @"AccessGroup";
NSString*   const     kstrKeyCreationDate                     = @"CreationDate";
NSString*   const     kstrKeyModificationDate                 = @"ModificationDate";
NSString*   const     kstrKeyDescription                      = @"Description";
NSString*   const     kstrKeyComment                          = @"Comment";
NSString*   const     kstrKeyCreator                          = @"Creator";
NSString*   const     kstrKeyType                             = @"Type";
NSString*   const     kstrKeyLabel                            = @"Label";
NSString*   const     kstrKeyIsInvisible                      = @"Invisible";
NSString*   const     kstrKeyIsNegative                       = @"Negative";
NSString*   const     kstrKeyAccount                          = @"Account";
NSString*   const     kstrKeyService                          = @"Service";
NSString*   const     kstrKeyGeneric                          = @"Generic";
NSString*   const     kstrKeyPassword                         = @"Password";
NSString*   const     kstrKeyDomain                           = @"Domain";
NSString*   const     kstrKeyServer                           = @"Server";
NSString*   const     kstrKeyProtocol                         = @"Protocol";
NSString*   const     kstrKeyAuthType                         = @"AuthenticationType";
NSString*   const     kstrKeyPort                             = @"Port";
NSString*   const     kstrKeyPath                             = @"Path";
NSString*   const     kstrKeyCertType                         = @"CertificateType";
NSString*   const     kstrKeyCertEncoding                     = @"CertificateEncoding";
NSString*   const     kstrKeySerialNumber                     = @"SerialNumber";
NSString*   const     kstrKeySubjectKeyId                     = @"SubjectKeyId";
NSString*   const     kstrKeyPublicKeyHash                    = @"PublicKeyHash";
NSString*   const     kstrKeySubject                          = @"Subject";
NSString*   const     kstrKeyIssuer                           = @"Issuer";
NSString*   const     kstrKeySummary                          = @"Summary";
NSString*   const     kstrKey_KeyClass                        = @"KeyClass";
NSString*   const     kstrKeyAppLabel                         = @"ApplicationLabel";
NSString*   const     kstrKeyIsPermanent                      = @"Permanent";
NSString*   const     kstrKeyAppTag                           = @"ApplicationTag";
NSString*   const     kstrKey_KeyType                         = @"KeyType";
NSString*   const     kstrKey_KeySize                         = @"KeySizeInBits";
NSString*   const     kstrKeyEffKeySize                       = @"EffectiveKeySizeInBits";
NSString*   const     kstrKeyCanEncrypt                       = @"CanEncrypt";
NSString*   const     kstrKeyCanDecrypt                       = @"CanDecrypt";
NSString*   const     kstrKeyCanDerive                        = @"CanDerive";
NSString*   const     kstrKeyCanSign                          = @"CanSign";
NSString*   const     kstrKeyCanVerify                        = @"CanVerify";
NSString*   const     kstrKeyCanWrap                          = @"CanWrap";
NSString*   const     kstrKeyCanUnwrap                        = @"CanUnwrap";
NSString*   const     kstrKey_KeyValue                        = @"Key";

#pragma mark Accessibility Values
NSString*   const     kstrAccessibleAfterFirstUnlock          = @"Available after the device is first unlocked after reboot";
NSString*   const     kstrAccessibleAfterFirstUnlockDevice    = @"Available after the device is first unlocked after reboot [Per Device]";
NSString*   const     kstrAccessibleAlways                    = @"Available anytime (device locked or not)";
NSString*   const     kstrAccessibleAlwaysDeviceOnly          = @"Available anytime (device locked or not) [Per Device]";
NSString*   const     kstrAccessibleOnUnlock                  = @"Available only when device is unlocked";
NSString*   const     kstrAccessibleOnUnlockDeviceOnly        = @"Available only when device is unlocked [Per Device]";

#pragma mark Protocol Values
NSString*   const     kstrProtocolFTP                         = @"FTP";
NSString*   const     kstrProtocolFTPClient                   = @"FTP client account";
NSString*   const     kstrProtocolHTTP                        = @"HTTP";
NSString*   const     kstrProtocolIRC                         = @"IRC";
NSString*   const     kstrProtocolNNTP                        = @"NNTP";
NSString*   const     kstrProtocolPOP3                        = @"POP3";
NSString*   const     kstrProtocolSMTP                        = @"SMTP";
NSString*   const     kstrProtocolSOCKS                       = @"SOCKS";
NSString*   const     kstrProtocolIMAP                        = @"IMAP";
NSString*   const     kstrProtocolLDAP                        = @"LDAP";
NSString*   const     kstrProtocolAppleTalk                   = @"AppleTalk";
NSString*   const     kstrProtocolAFP                         = @"AFP over TCP";
NSString*   const     kstrProtocolTelnet                      = @"Telnet";
NSString*   const     kstrProtocolSSH                         = @"SSH";
NSString*   const     kstrProtocolFTPS                        = @"FTP over TLS/SSL";
NSString*   const     kstrProtocolHTTPS                       = @"HTTPS";
NSString*   const     kstrProtocolFTPProxy                    = @"FTP Proxy";
NSString*   const     kstrProtocolHTTPProxy                   = @"HTTP Proxy";
NSString*   const     kstrProtocolHTTPSProxy                  = @"HTTPS Proxy";
NSString*   const     kstrProtocolSMB                         = @"SMB";
NSString*   const     kstrProtocolRTSP                        = @"RTSP";
NSString*   const     kstrProtocolRTSPProxy                   = @"RTSP Proxy";
NSString*   const     kstrProtocolDAAP                        = @"DAAP";
NSString*   const     kstrProtocolEPPC                        = @"EPPC - Remote Apple Events";
NSString*   const     kstrProtocolIPP                         = @"IPP";
NSString*   const     kstrProtocolNTTPS                       = @"NNTPS";
NSString*   const     kstrProtocolLDAPS                       = @"LDAPS";
NSString*   const     kstrProtocolTelnetS                     = @"TelnetS";
NSString*   const     kstrProtocolIMAPS                       = @"IMAPS";
NSString*   const     kstrProtocolIRCS                        = @"IRCS";
NSString*   const     kstrProtocolPOP3S                       = @"POP3S";

#pragma mark Authentication Type Values
NSString*   const     kstrAuthTypeNTLM                        = @"NTLM";
NSString*   const     kstrAuthTypeMSN                         = @"MSN";
NSString*   const     kstrAuthTypeDPA                         = @"DPA";
NSString*   const     kstrAuthTypeRPA                         = @"RPA";
NSString*   const     kstrAuthTypeHTTPBasic                   = @"HTTP Basic";
NSString*   const     kstrAuthTypeHTTPDigest                  = @"HTTP Digest";
NSString*   const     kstrAuthTypeHTTPForm                    = @"HTTP Form";
NSString*   const     kstrAuthTypeDefault                     = @"Default";

#pragma mark Certificate Type Values
NSString*   const     kstrCertTypeUnknown                     = @"Unknown";
NSString*   const     kstrCertTypeX509V1                      = @"X509_v1";
NSString*   const     kstrCertTypeX509V2                      = @"X509_v2";
NSString*   const     kstrCertTypeX509V3                      = @"X509_v3";
NSString*   const     kstrCertTypePGP                         = @"PGP";
NSString*   const     kstrCertTypeSPKI                        = @"SPKI";
NSString*   const     kstrCertTypeSDSIV1                      = @"SDSI_v1";
NSString*   const     kstrCertTypeIntel                       = @"Intel";
NSString*   const     kstrCertTypeX509                        = @"X509";
NSString*   const     kstrCertTypeX9                          = @"X9";
NSString*   const     kstrCertTypeTuple                       = @"Tuple";
NSString*   const     kstrCertTypeACLEntry                    = @"ACL_Entry";
NSString*   const     kstrCertTypeMultiple                    = @"Multiple";
NSString*   const     kstrCertTypeLast                        = @"Last";

#pragma mark Certificate Encoding Values
NSString*   const     kstrCertEncodingUnkown                  = @"Unknown";
NSString*   const     kstrCertEncodingCustom                  = @"Custom";
NSString*   const     kstrCertEncodingBER                     = @"BER";
NSString*   const     kstrCertEncodingDER                     = @"DER";
NSString*   const     kstrCertEncodingNDR                     = @"NDR";
NSString*   const     kstrCertEncodingSXPR                    = @"SXPR";
NSString*   const     kstrCertEncodingPGP                     = @"PGP";
NSString*   const     kstrCertEncodingMultiple                = @"Multiple";
NSString*   const     kstrCertEncodingLast                    = @"Last";

#pragma mark Key Class Values
NSString*   const     kstrKeyClassPublic                      = @"Public Key";
NSString*   const     kstrKeyClassPrivate                     = @"Private Key";
NSString*   const     kstrKeyClassSymmetric                   = @"Symmetric Key";

#pragma mark Data and Analysis Report Constants
NSString*   const     kstrDataAndReportsDir                  = @"DataAndAnalysisReports";
NSString*   const     kstrDataReportFile                     = @"KeychainDataExport.jsonp";
NSString*   const     kstrAnalysisReportFile                 = @"KeychainAnalysisReport.jsonp";
NSString*   const     kstrDataReportJSONFunction             = @"displayJSONData";
NSString*   const     kstrAnalysisReportJSONFunction         = @"displayAnalysisJSONData";
NSString*   const     kstrDataReportViewerFileName           = @"iOSKeychainDataViewer";
NSString*   const     kstrDataReportViewerFileExt            = @"htm";
NSString*   const     kstrAnalysisReportViewerFileName       = @"iOSKeychainAnalysisReportViewer";
NSString*   const     kstrAnalysisReportViewerFileExt        = @"htm";
NSString*   const     kstrReportHeaderImageFileName          = @"fs_header_image";
NSString*   const     kstrReportHeaderImageFileExt           = @"jpg";

#pragma mark Keychain Analysis Result Dictionary Keys
NSString*   const     kstrKeyWeakPasswordItems                = @"WeakPasswordCheckResults";
NSString*   const     kstrKeyWeakAuthItems                    = @"WeakAuthenticationCheckResults";
NSString*   const     kstrKeyWeakProtocolItems                = @"WeakProtocolCheckResults";
NSString*   const     kstrKeyWeakKeyItems                     = @"WeakKeyCheckResults";
NSString*   const     kstrKeyWeakAccessibilityItems           = @"WeakAccessibilityCheckResults";

#pragma mark Analysis Result Item Attributes
NSString*   const     kstrKeyResultItemType                   = @"ResultItemType";

#pragma mark Analysis Result Item Types
NSString*   const     kstrResultItemGenericPassword           = @"GenericPassword";
NSString*   const     kstrResultItemInternetPassword          = @"InternetPassword";
NSString*   const     kstrResultItemCertificate               = @"Certificate";
NSString*   const     kstrResultItemKey                       = @"Key";
NSString*   const     kstrResultItemIdentity                  = @"Identity";

#pragma mark Weak Password Check Constants
const   unsigned int  kWeakPassword_MaxLen                    = 7;

#pragma markWeak Protocol Check Constants
NSString*   const     kstrInsecurePortFTP                     = @"21";
NSString*   const     kstrInsecurePortHTTP                    = @"80";
NSString*   const     kstrInsecurePortTelnet                  = @"23";
NSString*   const     kstrInsecurePortNNTP                    = @"119";
NSString*   const     kstrInsecurePortPOP3                    = @"110";
NSString*   const     kstrInsecurePortIMAP                    = @"143";
NSString*   const     kstrInsecurePortIRC                     = @"194";
NSString*   const     kstrInsecurePortLDAP                    = @"389";

#pragma mark Weak Key Check Constants 
//The symmetric key is represented as hex string - <a9391957 621ecb53 9f88c709 ac24e795>.
//The length of a 128 bit key is 37 [32 (hex characters) + 3 (spaces) +2 (starting and ending bracket)]
const unsigned int    kStrongSymmKey_MinLengthInHexChars      = 37;
const unsigned int    kStrongAsymmKey_MinLengthInBits         = 1024;

#pragma mark Confirmation Dialog Messages
NSString*   const     kstrConfirmationDialogErrorMsg          = @"Error occured while processing the request. See console for log messages";
NSString*   const     kstrConfirmationDialogSuccessMsg        = @"Operation successfully completed.\n\nData has been written to the file - ";

#pragma mark Dialog/View Titles
NSString*   const     kstrMainViewTitle                       = @"iOSKeychain Analyzer";
NSString*   const     kstrConfirmationView_ExportData         = @"Export Keychain Data";
NSString*   const     kstrConfirmationView_AnalyzeData        = @"Analyze Keychain Data";

@end



