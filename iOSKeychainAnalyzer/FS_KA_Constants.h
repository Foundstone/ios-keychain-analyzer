//
//  FS_KA_Constants.h
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/15/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FS_KA_Constants : NSObject

@end

#pragma mark Count/Initial Size Constants
extern const   unsigned int  kTypesOfKeychainItems;
extern const   unsigned int  kNumOfAttributesPerKeychainItem;
extern const   unsigned int  kInitialNumOfGenericPasswords;
extern const   unsigned int  kInitialNumOfInternetPasswords;
extern const   unsigned int  kInitialNumOfCertificates;
extern const   unsigned int  kInitialNumOfKeys;
extern const   unsigned int  kInitialNumOfIdentities;
extern const   unsigned int  kNumofKeychainAnalysisChecks;
extern const   unsigned int  kNumOfAttributesPerAnalysisResultItem;
extern const   unsigned int  kInitialNumOfWeakPasswordItems;
extern const   unsigned int  kInitialNumOfWeakAuthenticationItems;
extern const   unsigned int  kInitialNumOfWeakProtocolItems;
extern const   unsigned int  kInitialNumOfWeakKeyItems;
extern const   unsigned int  kInitialNumOfWeakAccessibilityItems;

#pragma mark Result Dictionary Keys
extern NSString*   const     kstrKeyGenericPasswords;
extern NSString*   const     kstrKeyInternetPasswords;
extern NSString*   const     kstrKeyCertificates;
extern NSString*   const     kstrKeyKeys;
extern NSString*   const     kstrKeyIdentities;

#pragma mark Keychain Item Attributes
extern NSString*   const     kstrKeyAccessible;
extern NSString*   const     kstrKeyAccessGroup;
extern NSString*   const     kstrKeyCreationDate;
extern NSString*   const     kstrKeyModificationDate;
extern NSString*   const     kstrKeyDescription;
extern NSString*   const     kstrKeyComment;
extern NSString*   const     kstrKeyCreator;
extern NSString*   const     kstrKeyType;
extern NSString*   const     kstrKeyLabel;
extern NSString*   const     kstrKeyIsInvisible;
extern NSString*   const     kstrKeyIsNegative;
extern NSString*   const     kstrKeyAccount;
extern NSString*   const     kstrKeyService;
extern NSString*   const     kstrKeyGeneric;
extern NSString*   const     kstrKeyPassword;
extern NSString*   const     kstrKeyDomain;
extern NSString*   const     kstrKeyServer;
extern NSString*   const     kstrKeyProtocol;
extern NSString*   const     kstrKeyAuthType;
extern NSString*   const     kstrKeyPort;
extern NSString*   const     kstrKeyPath;
extern NSString*   const     kstrKeyCertType;
extern NSString*   const     kstrKeyCertEncoding;
extern NSString*   const     kstrKeySerialNumber;
extern NSString*   const     kstrKeySubjectKeyId;
extern NSString*   const     kstrKeyPublicKeyHash;
extern NSString*   const     kstrKeySubject;
extern NSString*   const     kstrKeyIssuer;
extern NSString*   const     kstrKeySummary;
extern NSString*   const     kstrKey_KeyClass;
extern NSString*   const     kstrKeyAppLabel;
extern NSString*   const     kstrKeyIsPermanent;
extern NSString*   const     kstrKeyAppTag;
extern NSString*   const     kstrKey_KeyType;
extern NSString*   const     kstrKey_KeySize;
extern NSString*   const     kstrKeyEffKeySize;
extern NSString*   const     kstrKeyCanEncrypt;
extern NSString*   const     kstrKeyCanDecrypt;
extern NSString*   const     kstrKeyCanDerive;
extern NSString*   const     kstrKeyCanSign;
extern NSString*   const     kstrKeyCanVerify;
extern NSString*   const     kstrKeyCanWrap;
extern NSString*   const     kstrKeyCanUnwrap;
extern NSString*   const     kstrKey_KeyValue;

#pragma mark Accessibility Values
extern NSString*   const     kstrAccessibleAfterFirstUnlock;
extern NSString*   const     kstrAccessibleAfterFirstUnlockDevice;
extern NSString*   const     kstrAccessibleAlways;
extern NSString*   const     kstrAccessibleAlwaysDeviceOnly;
extern NSString*   const     kstrAccessibleOnUnlock;
extern NSString*   const     kstrAccessibleOnUnlockDeviceOnly;

#pragma mark Protocol Values
extern NSString*   const     kstrProtocolFTP;
extern NSString*   const     kstrProtocolFTPClient;
extern NSString*   const     kstrProtocolHTTP;
extern NSString*   const     kstrProtocolIRC;
extern NSString*   const     kstrProtocolNNTP;
extern NSString*   const     kstrProtocolPOP3;
extern NSString*   const     kstrProtocolSMTP;
extern NSString*   const     kstrProtocolSOCKS;
extern NSString*   const     kstrProtocolIMAP;
extern NSString*   const     kstrProtocolLDAP;
extern NSString*   const     kstrProtocolAppleTalk;
extern NSString*   const     kstrProtocolAFP;
extern NSString*   const     kstrProtocolTelnet;
extern NSString*   const     kstrProtocolSSH;
extern NSString*   const     kstrProtocolFTPS;
extern NSString*   const     kstrProtocolHTTPS;
extern NSString*   const     kstrProtocolFTPProxy;
extern NSString*   const     kstrProtocolHTTPProxy;
extern NSString*   const     kstrProtocolHTTPSProxy;
extern NSString*   const     kstrProtocolSMB;
extern NSString*   const     kstrProtocolRTSP;
extern NSString*   const     kstrProtocolRTSPProxy;
extern NSString*   const     kstrProtocolDAAP;
extern NSString*   const     kstrProtocolEPPC;
extern NSString*   const     kstrProtocolIPP;
extern NSString*   const     kstrProtocolNTTPS;
extern NSString*   const     kstrProtocolLDAPS;
extern NSString*   const     kstrProtocolTelnetS;
extern NSString*   const     kstrProtocolIMAPS;
extern NSString*   const     kstrProtocolIRCS;
extern NSString*   const     kstrProtocolPOP3S;

#pragma mark Authentication Type Values
extern NSString*   const     kstrAuthTypeNTLM;
extern NSString*   const     kstrAuthTypeMSN;
extern NSString*   const     kstrAuthTypeDPA;
extern NSString*   const     kstrAuthTypeRPA;
extern NSString*   const     kstrAuthTypeHTTPBasic;
extern NSString*   const     kstrAuthTypeHTTPDigest;
extern NSString*   const     kstrAuthTypeHTTPForm;
extern NSString*   const     kstrAuthTypeDefault;

#pragma mark Certificate Type Values
extern NSString*   const     kstrCertTypeUnknown;
extern NSString*   const     kstrCertTypeX509V1;
extern NSString*   const     kstrCertTypeX509V2;
extern NSString*   const     kstrCertTypeX509V3;
extern NSString*   const     kstrCertTypePGP;
extern NSString*   const     kstrCertTypeSPKI;
extern NSString*   const     kstrCertTypeSDSIV1;
extern NSString*   const     kstrCertTypeIntel;
extern NSString*   const     kstrCertTypeX509;
extern NSString*   const     kstrCertTypeX9;
extern NSString*   const     kstrCertTypeTuple;
extern NSString*   const     kstrCertTypeACLEntry;
extern NSString*   const     kstrCertTypeMultiple;
extern NSString*   const     kstrCertTypeLast;

#pragma mark Certificate Encoding Values
extern NSString*   const     kstrCertEncodingUnkown;
extern NSString*   const     kstrCertEncodingCustom;
extern NSString*   const     kstrCertEncodingBER;
extern NSString*   const     kstrCertEncodingDER;
extern NSString*   const     kstrCertEncodingNDR;
extern NSString*   const     kstrCertEncodingSXPR;
extern NSString*   const     kstrCertEncodingPGP;
extern NSString*   const     kstrCertEncodingMultiple;
extern NSString*   const     kstrCertEncodingLast;

#pragma mark Key Class Values
extern NSString*   const     kstrKeyClassPublic;
extern NSString*   const     kstrKeyClassPrivate;
extern NSString*   const     kstrKeyClassSymmetric;

#pragma mark Data and Analysis Report Constants
extern NSString*   const     kstrDataAndReportsDir;
extern NSString*   const     kstrDataReportFile;
extern NSString*   const     kstrAnalysisReportFile;
extern NSString*   const     kstrDataReportJSONFunction;
extern NSString*   const     kstrAnalysisReportJSONFunction;
extern NSString*   const     kstrDataReportViewerFileName;
extern NSString*   const     kstrDataReportViewerFileExt;
extern NSString*   const     kstrAnalysisReportViewerFileName;
extern NSString*   const     kstrAnalysisReportViewerFileExt;
extern NSString*   const     kstrReportHeaderImageFileName;
extern NSString*   const     kstrReportHeaderImageFileExt;

#pragma mark Keychain Analysis Result Dictionary Keys
extern NSString*   const     kstrKeyWeakPasswordItems;
extern NSString*   const     kstrKeyWeakAuthItems;
extern NSString*   const     kstrKeyWeakProtocolItems;
extern NSString*   const     kstrKeyWeakKeyItems;
extern NSString*   const     kstrKeyWeakAccessibilityItems;

#pragma mark Analysis Result Item Attributes
extern NSString*   const     kstrKeyResultItemType;

#pragma mark Analysis Result Item Types
extern NSString*   const     kstrResultItemGenericPassword;
extern NSString*   const     kstrResultItemInternetPassword;
extern NSString*   const     kstrResultItemCertificate;
extern NSString*   const     kstrResultItemKey;
extern NSString*   const     kstrResultItemIdentity;

#pragma mark Weak Password Check Constants
extern const   unsigned int  kWeakPassword_MaxLen;

#pragma markWeak Protocol Check Constants
extern NSString*   const     kstrInsecurePortFTP;
extern NSString*   const     kstrInsecurePortHTTP;
extern NSString*   const     kstrInsecurePortTelnet;
extern NSString*   const     kstrInsecurePortNNTP;
extern NSString*   const     kstrInsecurePortPOP3;
extern NSString*   const     kstrInsecurePortIMAP;
extern NSString*   const     kstrInsecurePortIRC;
extern NSString*   const     kstrInsecurePortLDAP;

#pragma mark Weak Key Check Constants
extern const unsigned int    kStrongSymmKey_MinLengthInHexChars;
extern const unsigned int    kStrongAsymmKey_MinLengthInBits;

#pragma mark Confirmation Dialog Messages
extern NSString*   const     kstrConfirmationDialogErrorMsg;
extern NSString*   const     kstrConfirmationDialogSuccessMsg;

#pragma mark Dialog/View Titles
extern NSString*   const     kstrMainViewTitle;
extern NSString*   const     kstrConfirmationView_ExportData;
extern NSString*   const     kstrConfirmationView_AnalyzeData;