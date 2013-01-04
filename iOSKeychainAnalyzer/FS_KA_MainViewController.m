//
//  FS_KA_MainViewController.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/10/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <Security/Security.h>

#import "FS_KA_MainViewController.h"
#import "FS_KA_Helper.h"
#import "FS_KA_Constants.h"

@interface FS_KA_MainViewController ()

@end

@implementation FS_KA_MainViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view.
    
    //[self setTitle:kstrMainViewTitle];
    
    bIsKeychainLoaded = NO;
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

- (UINavigationItem *)navigationItem
{
    //Configure the navigation bar item
    //  Set the title
    //This method is called by the framework as it displays the view so you do not need to invoke it manually
    
    if (nil == uiNavItem)
    {
        uiNavItem = [super navigationItem];
        [uiNavItem setTitle:kstrMainViewTitle];
    }

    return uiNavItem;
}


#pragma mark - UI Events
- (IBAction)exportKeychainData: (id)sender
{
    BOOL bErrorOccured = NO;
    
    if (NO == bIsKeychainLoaded)
    {
        [self loadKeychain];
    }

    NSString* strKeychainDataJSONP = [self convertKeychainDataToJSONP];
    if (nil == strKeychainDataJSONP)
    {
        bErrorOccured = YES;
    }
    else
    {
        NSURL* dataDir = [self createDataDirectory];
        if (nil == dataDir)
        {
            bErrorOccured = YES;
        }
        else
        {
            [self copyDataViewerHTMLToDataDirectory:dataDir];
            [self saveKeychainData:strKeychainDataJSONP toReportDir:dataDir];
        }
    }
    
    [self launchConfirmationDialogForDataExport:bErrorOccured];
}

- (IBAction)analyzeKeychainData:(id)sender
{
    BOOL bErrorOccured = NO;

    if (NO == bIsKeychainLoaded)
    {
        [self loadKeychain];
    }

    [self runKeychainAnalysis];

    NSString* strAnalysisDataJSONP = [self convertstrAnalysisDataToJSONP];
    if (nil == strAnalysisDataJSONP)
    {
        bErrorOccured = YES;
    }
    else
    {
        NSURL* dataDir = [self createDataDirectory];
        if (nil == dataDir)
        {
            bErrorOccured = YES;
        }
        else
        {
            [self copyAnalysisReportViewerHTMLToDataDirectory:dataDir];
            [self saveAnalysisData:strAnalysisDataJSONP toReportDir:dataDir];
        }
    }

    [self launchConfirmationDialogForAnalysisReport:bErrorOccured];
}

- (IBAction)aboutKeychainAnalyzer:(id)sender
{
    FS_KA_AboutDialogViewController *aboutDialogController = [[FS_KA_AboutDialogViewController alloc]
                                                                            initWithNibName:@"AboutDialogView" bundle:nil];
    [aboutDialogController setModalTransitionStyle:UIModalTransitionStyleCoverVertical];
    [aboutDialogController setDelegate:self];

    [[self navigationController]pushViewController:aboutDialogController animated:YES];
    
    return;
}

#pragma mark - Top Level Functions
- (void)loadKeychain
{
    allKeychainItems = [[NSMutableDictionary alloc]initWithCapacity:kTypesOfKeychainItems];
   
    [self loadGenericPasswords];
    
    [self loadInternetPasswords];
    
    [self loadCertificates];
    
    [self loadKeys];
    
    [self loadIdentities];
    
    bIsKeychainLoaded = YES;
    
    return;
}

- (void)runKeychainAnalysis
{
    keychainAnalysisResults = [[NSMutableDictionary alloc]initWithCapacity:kNumofKeychainAnalysisChecks];
    
    [self checkKeychainItemsForWeakPasswords];
    
    [self checkKeychainItemsForWeakAuthScheme];

    [self checkKeychainItemsForWeakProtocols];
    
    [self checkKeychainItemsForWeakKeys];

    [self checkKeychainItemsForInsecureAccessibility];
    
    return;
}

#pragma mark - Load Generic Passwords

- (void)loadGenericPasswords
{
    NSDictionary* queryParamsGenericPasswords = [self createKeychainQueryForGenericPasswords];
    
    NSArray* resultItems = [self searchKeychainUsingQuery:queryParamsGenericPasswords];
    
    if (nil == resultItems) //Either no items found or an error occured. Either way do not proceed
        return;
    
    [self addGenericPasswords:resultItems];
    
    return;
}

- (NSDictionary*)createKeychainQueryForGenericPasswords
{
    NSDictionary *dictQueryParams = [NSDictionary dictionaryWithObjectsAndKeys:
                                     (__bridge id)kSecClassGenericPassword,     (__bridge id)kSecClass,
                                     (__bridge id)kSecMatchLimitAll,            (__bridge id)kSecMatchLimit,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnAttributes,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnData,
                                     nil];
    
    return dictQueryParams;
    
}

- (void) addGenericPasswords:(NSArray*)resultItems
{
    NSMutableArray*         keychainGenericPasswords        = [[NSMutableArray alloc]       initWithCapacity:kInitialNumOfGenericPasswords];

    for (unsigned int uiIndex = 0; uiIndex < [resultItems count]; uiIndex++)
    {
        NSMutableDictionary*    dictReadableSecItemAttributes   = [[NSMutableDictionary alloc]  initWithCapacity:kNumOfAttributesPerKeychainItem];
        
        NSDictionary *dictSecItemAttributes = (NSDictionary *)([resultItems objectAtIndex:uiIndex]);
                
        [self addCommonAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addGenericPasswordAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [keychainGenericPasswords addObject:dictReadableSecItemAttributes];
    }
    
    [allKeychainItems setObject:keychainGenericPasswords forKey:kstrKeyGenericPasswords];
    
    return;
}

- (void)addGenericPasswordAttributesFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    if(nil == dictSecItemAttributes) //nothing to add
        return;
    
    if (0 >= [dictSecItemAttributes count])
        return; //nothing to add
    
    if(nil == resultDictionary) //result dictionary is nil
        return;
    
    NSString* strAccount        = [FS_KA_Helper getAccountForSecItem:dictSecItemAttributes];
    NSString* strService        = [FS_KA_Helper getServiceForSecItem:dictSecItemAttributes];
    NSString* strGeneric        = [FS_KA_Helper getGenericForSecItem:dictSecItemAttributes];
    NSString* strPassword       = [FS_KA_Helper getPasswordForSecItem:dictSecItemAttributes];
    
    [resultDictionary setValue:strAccount   forKey:kstrKeyAccount];
    [resultDictionary setValue:strService   forKey:kstrKeyService];
    [resultDictionary setValue:strGeneric   forKey:kstrKeyGeneric];
    [resultDictionary setValue:strPassword  forKey:kstrKeyPassword];
    
    return;
}


#pragma mark - Load Internet Passwords
- (void)loadInternetPasswords
{
    NSDictionary* queryParamsInternetPasswords = [self createKeychainQueryForInternetPasswords];
    
    NSArray* resultItems = [self searchKeychainUsingQuery:queryParamsInternetPasswords];
    
    if (nil == resultItems) //Either no items found or an error occured. Either way do not proceed
        return;
    
    [self addInternetPasswords:resultItems];
    
    return;
}

- (NSDictionary*)createKeychainQueryForInternetPasswords
{
    NSDictionary *dictQueryParams = [NSDictionary dictionaryWithObjectsAndKeys:
                                     (__bridge id)kSecClassInternetPassword,     (__bridge id)kSecClass,
                                     (__bridge id)kSecMatchLimitAll,            (__bridge id)kSecMatchLimit,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnAttributes,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnData,
                                     nil];
    
    return dictQueryParams;
    
}

- (void) addInternetPasswords:(NSArray*)resultItems
{
    NSMutableArray*         keychainInternetPasswords        = [[NSMutableArray alloc]       initWithCapacity:kInitialNumOfInternetPasswords];
    
    for (unsigned int uiIndex = 0; uiIndex < [resultItems count]; uiIndex++)
    {
        NSMutableDictionary*    dictReadableSecItemAttributes   = [[NSMutableDictionary alloc]  initWithCapacity:kNumOfAttributesPerKeychainItem];
        
        NSDictionary *dictSecItemAttributes = (NSDictionary *)([resultItems objectAtIndex:uiIndex]);
        
        [self addCommonAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addInternetPasswordAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [keychainInternetPasswords addObject:dictReadableSecItemAttributes];
    }
    
    [allKeychainItems setObject:keychainInternetPasswords forKey:kstrKeyInternetPasswords];
    
    return;
}

- (void)addInternetPasswordAttributesFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    if(nil == dictSecItemAttributes) //nothing to add
        return;
    
    if (0 >= [dictSecItemAttributes count])
        return; //nothing to add
    
    if(nil == resultDictionary) //result dictionary is nil
        return;
    
    NSString* strAccount        = [FS_KA_Helper getAccountForSecItem:dictSecItemAttributes];
    NSString* strSecDomain      = [FS_KA_Helper getSecurityDomainForSecItem:dictSecItemAttributes];
    NSString* strServer         = [FS_KA_Helper getServerForSecItem:dictSecItemAttributes];
    NSString* strProtocol       = [FS_KA_Helper getProtocolForSecItem:dictSecItemAttributes];
    NSString* strAuthType       = [FS_KA_Helper getAuthenticationTypeForSecItem:dictSecItemAttributes];
    NSString* strPort           = [FS_KA_Helper getPortForSecItem:dictSecItemAttributes];
    NSString* strPath           = [FS_KA_Helper getPathForSecItem:dictSecItemAttributes];
    NSString* strPassword       = [FS_KA_Helper getPasswordForSecItem:dictSecItemAttributes];
    
    [resultDictionary setValue:strAccount   forKey:kstrKeyAccount];
    [resultDictionary setValue:strSecDomain forKey:kstrKeyDomain];
    [resultDictionary setValue:strServer    forKey:kstrKeyServer];
    [resultDictionary setValue:strProtocol  forKey:kstrKeyProtocol];
    [resultDictionary setValue:strAuthType  forKey:kstrKeyAuthType];
    [resultDictionary setValue:strPort      forKey:kstrKeyPort];
    [resultDictionary setValue:strPath      forKey:kstrKeyPath];
    [resultDictionary setValue:strPassword  forKey:kstrKeyPassword];
    
    return;
}


#pragma mark - Load Certificates
- (void)loadCertificates
{
    NSDictionary* queryParamsCertificates = [self createKeychainQueryForCertificates];
    
    NSArray* resultItems = [self searchKeychainUsingQuery:queryParamsCertificates];
    
    if (nil == resultItems) //Either no items found or an error occured. Either way do not proceed
        return;
    
    [self addCertificates:resultItems];
    
    return;
}

- (NSDictionary*)createKeychainQueryForCertificates
{
    NSDictionary *dictQueryParams = [NSDictionary dictionaryWithObjectsAndKeys:
                                     (__bridge id)kSecClassCertificate,         (__bridge id)kSecClass,
                                     (__bridge id)kSecMatchLimitAll,            (__bridge id)kSecMatchLimit,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnAttributes,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnData,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnRef,
                                     nil];
    
    return dictQueryParams;
    
}

- (void) addCertificates:(NSArray*)resultItems
{
    NSMutableArray*         keychainCertificates            = [[NSMutableArray alloc]       initWithCapacity:kInitialNumOfCertificates];
    
    for (unsigned int uiIndex = 0; uiIndex < [resultItems count]; uiIndex++)
    {
        NSMutableDictionary*    dictReadableSecItemAttributes   = [[NSMutableDictionary alloc]  initWithCapacity:kNumOfAttributesPerKeychainItem];
        
        NSDictionary *dictSecItemAttributes = (NSDictionary *)([resultItems objectAtIndex:uiIndex]);
        
        [self addCommonAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addCertificateAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];

        [self addCertificateSummaryForCertificateFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [keychainCertificates addObject:dictReadableSecItemAttributes];
    }
    
    [allKeychainItems setObject:keychainCertificates forKey:kstrKeyCertificates];
    
    return;
}

- (void)addCertificateAttributesFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    if(nil == dictSecItemAttributes) //nothing to add
        return;
    
    if (0 >= [dictSecItemAttributes count])
        return; //nothing to add
    
    if(nil == resultDictionary) //result dictionary is nil
        return;
    
    NSString* strCertType =         [FS_KA_Helper getCertificateTypeForSecItem:dictSecItemAttributes];
    NSString* strCertEncoding =     [FS_KA_Helper getCertificateEncodingForSecItem:dictSecItemAttributes];
    NSString* strSerialNum =        [FS_KA_Helper getSerialNumberForSecItem:dictSecItemAttributes];
    NSString* strSubjectKeyId =     [FS_KA_Helper getSubjectKeyIdForSecItem:dictSecItemAttributes];
    NSString* strPublicKeyHash =    [FS_KA_Helper getPublicKeyHashForSecItem:dictSecItemAttributes];

    //NSString* strValue =            [FS_KA_Helper getValueForSecItem:dictSecItemAttributes];
    //NSString* strSubject =          [FS_KA_Helper getSubjectForSecItem:dictSecItemAttributes];
    //NSString* strIssuer =           [FS_KA_Helper getIssuerForSecItem:dictSecItemAttributes];
    
    [resultDictionary setValue:strCertType      forKey:kstrKeyCertType];
    [resultDictionary setValue:strCertEncoding  forKey:kstrKeyCertEncoding];
    [resultDictionary setValue:strSerialNum     forKey:kstrKeySerialNumber];
    [resultDictionary setValue:strSubjectKeyId  forKey:kstrKeySubjectKeyId];
    [resultDictionary setValue:strPublicKeyHash forKey:kstrKeyPublicKeyHash];
    
    return;
}

- (void)addCertificateSummaryForCertificateFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    SecCertificateRef certRef =     (__bridge SecCertificateRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecValueRef)]);
    NSString* strSummary =          [FS_KA_Helper getSummaryForCert:certRef];
    
    [resultDictionary setValue:strSummary forKey:kstrKeySummary];
    
    return;
}

#pragma mark - Load Keys
- (void)loadKeys
{
    NSDictionary* queryParamsKeys = [self createKeychainQueryForKeys];
    
    NSArray* resultItems = [self searchKeychainUsingQuery:queryParamsKeys];
    
    if (nil == resultItems) //Either no items found or an error occured. Either way do not proceed
        return;
    
    [self addKeys:resultItems];
    
    return;
}

- (NSDictionary*)createKeychainQueryForKeys
{
    NSDictionary *dictQueryParams = [NSDictionary dictionaryWithObjectsAndKeys:
                                     (__bridge id)kSecClassKey,                 (__bridge id)kSecClass,
                                     (__bridge id)kSecMatchLimitAll,            (__bridge id)kSecMatchLimit,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnAttributes,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnData,
                                     nil];
    
    return dictQueryParams;
    
}

- (void) addKeys:(NSArray*)resultItems
{
    NSMutableArray*         keychainKeys                    = [[NSMutableArray alloc]       initWithCapacity:kInitialNumOfKeys];
    
    for (unsigned int uiIndex = 0; uiIndex < [resultItems count]; uiIndex++)
    {
        NSMutableDictionary*    dictReadableSecItemAttributes   = [[NSMutableDictionary alloc]  initWithCapacity:kNumOfAttributesPerKeychainItem];
        
        NSDictionary *dictSecItemAttributes = (NSDictionary *)([resultItems objectAtIndex:uiIndex]);
        
        [self addCommonAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addKeyAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [keychainKeys addObject:dictReadableSecItemAttributes];
    }
    
    [allKeychainItems setObject:keychainKeys forKey:kstrKeyKeys];
    
    return;
}

- (void)addKeyAttributesFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    if(nil == dictSecItemAttributes) //nothing to add
        return;
    
    if (0 >= [dictSecItemAttributes count])
        return; //nothing to add
    
    if(nil == resultDictionary) //result dictionary is nil
        return;
    
    NSString *strKeyClass =         [FS_KA_Helper getKeyClassForSecItem:dictSecItemAttributes];
    NSString *strAppLabel =         [FS_KA_Helper getApplicationLabelForSecItem:dictSecItemAttributes];
    NSString *strIsPermanent =      [FS_KA_Helper getIsPermanentForSecItem:dictSecItemAttributes];
    NSString *strAppTag =           [FS_KA_Helper getApplicationTagForSecItem:dictSecItemAttributes];
    NSString *strKeyType =          [FS_KA_Helper getKeyTypeForSecItem:dictSecItemAttributes];
    NSString *strKeySize =          [FS_KA_Helper getKeySizeInBitsForSecItem:dictSecItemAttributes];
    NSString *strEffKeySize =       [FS_KA_Helper getEffectiveKeySizeForSecItem:dictSecItemAttributes];
    NSString *strCanEncrypt =       [FS_KA_Helper getCanEncryptForSecItem:dictSecItemAttributes];
    NSString *strCanDecrypt =       [FS_KA_Helper getCanDecryptForSecItem:dictSecItemAttributes];
    NSString *strCanDerive =        [FS_KA_Helper getCanDeriveForSecItem:dictSecItemAttributes];
    NSString *strCanSign =          [FS_KA_Helper getCanSignForSecItem:dictSecItemAttributes];
    NSString *strCanVerify =        [FS_KA_Helper getCanVerifyForSecItem:dictSecItemAttributes];
    NSString *strCanWrap =          [FS_KA_Helper getCanWrapForSecItem:dictSecItemAttributes];
    NSString *strCanUnwrap =        [FS_KA_Helper getCanUnwrapForSecItem:dictSecItemAttributes];
    NSString *strKeyValue =         [FS_KA_Helper getKeyValueForSecItem:dictSecItemAttributes];
    
    [resultDictionary setValue:strKeyClass      forKey:kstrKey_KeyClass];
    [resultDictionary setValue:strAppLabel      forKey:kstrKeyAppLabel];
    [resultDictionary setValue:strIsPermanent   forKey:kstrKeyIsPermanent];
    [resultDictionary setValue:strAppTag        forKey:kstrKeyAppTag];
    [resultDictionary setValue:strKeyType       forKey:kstrKey_KeyType];
    [resultDictionary setValue:strKeySize       forKey:kstrKey_KeySize];
    [resultDictionary setValue:strEffKeySize    forKey:kstrKeyEffKeySize];
    [resultDictionary setValue:strCanEncrypt    forKey:kstrKeyCanEncrypt];
    [resultDictionary setValue:strCanDecrypt    forKey:kstrKeyCanDecrypt];
    [resultDictionary setValue:strCanDerive     forKey:kstrKeyCanDerive];
    [resultDictionary setValue:strCanSign       forKey:kstrKeyCanSign];
    [resultDictionary setValue:strCanVerify     forKey:kstrKeyCanVerify];
    [resultDictionary setValue:strCanWrap       forKey:kstrKeyCanWrap];
    [resultDictionary setValue:strCanUnwrap     forKey:kstrKeyCanUnwrap];
    [resultDictionary setValue:strKeyValue      forKey:kstrKey_KeyValue];

    return;
}


#pragma mark - Load Identities
- (void)loadIdentities
{
    NSDictionary* queryParamsIdentities = [self createKeychainQueryForIdentities];
    
    NSArray* resultItems = [self searchKeychainUsingQuery:queryParamsIdentities];
    
    if (nil == resultItems) //Either no items found or an error occured. Either way do not proceed
        return;
    
    [self addIdentities:resultItems];
    
    return;
}

- (NSDictionary*)createKeychainQueryForIdentities
{
    NSDictionary *dictQueryParams = [NSDictionary dictionaryWithObjectsAndKeys:
                                     (__bridge id)kSecClassIdentity,     (__bridge id)kSecClass,
                                     (__bridge id)kSecMatchLimitAll,            (__bridge id)kSecMatchLimit,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnAttributes,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnData,
                                     (__bridge id)kCFBooleanTrue,               (__bridge id)kSecReturnRef,
                                     nil];
    
    return dictQueryParams;
    
}

- (void) addIdentities:(NSArray*)resultItems
{
    NSMutableArray*         keychainIdentities        = [[NSMutableArray alloc]       initWithCapacity:kInitialNumOfIdentities];
    
    for (unsigned int uiIndex = 0; uiIndex < [resultItems count]; uiIndex++)
    {
        NSMutableDictionary*    dictReadableSecItemAttributes   = [[NSMutableDictionary alloc]  initWithCapacity:kNumOfAttributesPerKeychainItem];
        
        NSDictionary *dictSecItemAttributes = (NSDictionary *)([resultItems objectAtIndex:uiIndex]);
        
        [self addCommonAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
 
        [self addCertificateAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addCertificateSummaryForIdentityFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [self addKeyAttributesFrom:dictSecItemAttributes toDictionary:dictReadableSecItemAttributes];
        
        [keychainIdentities addObject:dictReadableSecItemAttributes];
    }
    
    [allKeychainItems setObject:keychainIdentities forKey:kstrKeyIdentities];
    
    return;
}

- (void)addCertificateSummaryForIdentityFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    NSString* strSummary = @"[Not Set]";
    
    SecIdentityRef identityRef =     (__bridge SecIdentityRef)([dictSecItemAttributes objectForKey:(__bridge id)(kSecValueRef)]);
    if (NULL != identityRef)
    {
        SecCertificateRef certRef;
        
        OSStatus resultStatus = SecIdentityCopyCertificate(identityRef, &certRef);
        if(errSecSuccess == resultStatus)
        {
            strSummary = [FS_KA_Helper getSummaryForCert:certRef];
            CFRelease(certRef);
        }
        else
        {
            NSLog(@"Error obtaining the certificate from the identity");
        }
    }
        
    [resultDictionary setValue:strSummary forKey:kstrKeySummary];
    
    return;
}

#pragma mark Analysis - Check for weak passwords
// We consider any passsword that matches either of the following conditions as weak -
//   1. Length less than 8 characters
//   2. Is NOT alphanumeric
//   3. Does NOT contain a special character
//
- (void)checkKeychainItemsForWeakPasswords
{
    NSMutableArray* weakPasswords = [[NSMutableArray alloc] initWithCapacity:kInitialNumOfWeakPasswordItems];

    [self checkGenericPasswordsForWeakPasswords:weakPasswords];
    [self checkInternetPasswordsForWeakPasswords:weakPasswords];

    [keychainAnalysisResults setValue:weakPasswords forKey:kstrKeyWeakPasswordItems];
    
    return;
}

- (void)checkGenericPasswordsForWeakPasswords:(NSMutableArray*)resultsArray
{
    NSArray* arrGenericPasswords = [allKeychainItems objectForKey:kstrKeyGenericPasswords];
    
    [self checkForWeakPasswords:arrGenericPasswords ofType:kstrResultItemGenericPassword andAddToResults:resultsArray];
    
    return;
}

- (void)checkInternetPasswordsForWeakPasswords:(NSMutableArray*)resultsArray
{
    NSArray* arrInternetPasswords = [allKeychainItems objectForKey:kstrKeyInternetPasswords];
    
    [self checkForWeakPasswords:arrInternetPasswords ofType:kstrResultItemInternetPassword andAddToResults:resultsArray];
    
    return;
}

- (void)checkForWeakPasswords:(NSArray*)arrPasswords ofType:(NSString*)strPasswordType andAddToResults:(NSMutableArray*)resultsArray
{
    for (unsigned int uiIndex = 0; uiIndex < [arrPasswords count]; uiIndex++)
    {
        NSDictionary *dictCurrentSecItem = [arrPasswords objectAtIndex:uiIndex];
        NSString* strPassword = [dictCurrentSecItem objectForKey:kstrKeyPassword];
        BOOL isPasswordWeak = [FS_KA_Helper checkIfPasswordIsWeak:strPassword];
        
        if (NO == isPasswordWeak)
            continue;
        
        NSMutableDictionary *dictAnalysisResultItem = [NSMutableDictionary dictionaryWithDictionary:dictCurrentSecItem];
        [dictAnalysisResultItem setValue:strPasswordType forKey:kstrKeyResultItemType];
        [resultsArray addObject:dictAnalysisResultItem];
    }
    
    return;
}

#pragma mark Analysis - Check for weak authentication scheme
- (void)checkKeychainItemsForWeakAuthScheme
{
    NSMutableArray* weakAuthSchemeItems = [[NSMutableArray alloc] initWithCapacity:kInitialNumOfWeakAuthenticationItems];
    
    [self checkInternetPasswordsForWeakAuthScheme:weakAuthSchemeItems];
    
    [keychainAnalysisResults setValue:weakAuthSchemeItems forKey:kstrKeyWeakAuthItems];

    return;
}

- (void) checkInternetPasswordsForWeakAuthScheme:(NSMutableArray*)resultsArray
{
    NSArray* arrInternetPasswords = [allKeychainItems objectForKey:kstrKeyInternetPasswords];

    for (unsigned int uiIndex = 0; uiIndex < [arrInternetPasswords count]; uiIndex++)
    {
        NSDictionary *dictCurrentSecItem = [arrInternetPasswords objectAtIndex:uiIndex];

        NSString* strAuthScheme = [dictCurrentSecItem objectForKey:kstrKeyAuthType];
        BOOL isAuthSchemeWeak   = [FS_KA_Helper checkIfAuthenticationSchemeIsWeak:strAuthScheme];
        
        if (NO == isAuthSchemeWeak)
            continue;

        NSMutableDictionary *dictAnalysisResultItem = [NSMutableDictionary dictionaryWithDictionary:dictCurrentSecItem];
        [dictAnalysisResultItem setValue:kstrResultItemInternetPassword forKey:kstrKeyResultItemType];
        [resultsArray addObject:dictAnalysisResultItem];
    }
    
    return;
}

#pragma mark Analysis - Check for weak protocols
- (void)checkKeychainItemsForWeakProtocols
{
    NSMutableArray* weakProtocolItems = [[NSMutableArray alloc] initWithCapacity:kInitialNumOfWeakProtocolItems];
    
    [self checkInternetPasswordsForWeakProtocols:weakProtocolItems];
    
    [keychainAnalysisResults setValue:weakProtocolItems forKey:kstrKeyWeakProtocolItems];
    
    return;
}

- (void) checkInternetPasswordsForWeakProtocols:(NSMutableArray*)resultsArray
{
    NSArray* arrInternetPasswords = [allKeychainItems objectForKey:kstrKeyInternetPasswords];
    
    for (unsigned int uiIndex = 0; uiIndex < [arrInternetPasswords count]; uiIndex++)
    {
        NSDictionary *dictCurrentSecItem = [arrInternetPasswords objectAtIndex:uiIndex];
        NSString* strProtocol                 = [dictCurrentSecItem objectForKey:kstrKeyProtocol];
        BOOL isProtocolWeak = [FS_KA_Helper checkIfProtocolIsWeak:strProtocol];
        
        if (NO == isProtocolWeak)
        {
            NSString* strPort = [dictCurrentSecItem objectForKey:kstrKeyPort];
            BOOL isInsecurePortBeingUsed = [FS_KA_Helper checkIfInsecurePortIsBeingUsed:strPort];
            
            if (NO == isInsecurePortBeingUsed)
                continue;
        }
        
        NSMutableDictionary *dictAnalysisResultItem = [NSMutableDictionary dictionaryWithDictionary:dictCurrentSecItem];
        [dictAnalysisResultItem setValue:kstrResultItemInternetPassword forKey:kstrKeyResultItemType];
        [resultsArray addObject:dictAnalysisResultItem];
    }
    
    return;
}

#pragma mark Analysis - Check for weak keys
- (void)checkKeychainItemsForWeakKeys
{
    NSMutableArray* weakKeysItems = [[NSMutableArray alloc] initWithCapacity:kInitialNumOfWeakKeyItems];
    
    [self checkKeysForWeakKeys:weakKeysItems];
    [self checkIdentitiesForWeakKeys:weakKeysItems];
    
    [keychainAnalysisResults setValue:weakKeysItems forKey:kstrKeyWeakKeyItems];
    
    return;
}

- (void) checkKeysForWeakKeys:(NSMutableArray*)resultsArray
{
    NSArray* arrKeys = [allKeychainItems objectForKey:kstrKeyKeys];
    
    [self checkForWeakKeys:arrKeys ofType:kstrResultItemKey andAddToResults:resultsArray];
    
    return;
}

- (void) checkIdentitiesForWeakKeys:(NSMutableArray*)resultsArray
{
    NSArray* arrIdentities = [allKeychainItems objectForKey:kstrKeyIdentities];
    
    [self checkForWeakKeys:arrIdentities ofType:kstrResultItemIdentity andAddToResults:resultsArray];
    
    return;
}

- (void)checkForWeakKeys:(NSArray*)arrItems ofType:(NSString*)strItemType andAddToResults:(NSMutableArray*)resultsArray
{
    for (unsigned int uiIndex = 0; uiIndex < [arrItems count]; uiIndex++)
    {
        NSDictionary *dictCurrentSecItem = [arrItems objectAtIndex:uiIndex];
        BOOL isKeyWeak = [FS_KA_Helper checkIfKeyIsWeak:dictCurrentSecItem];
        
        if (NO == isKeyWeak)
            continue;
        
        NSMutableDictionary *dictAnalysisResultItem = [NSMutableDictionary dictionaryWithDictionary:dictCurrentSecItem];
        [dictAnalysisResultItem setValue:strItemType forKey:kstrKeyResultItemType];
        [resultsArray addObject:dictAnalysisResultItem];
    }
    
    return;
}

#pragma mark Analysis - Check for weak accessibility
- (void)checkKeychainItemsForInsecureAccessibility
{
    NSMutableArray* weakAccessibilityItems = [[NSMutableArray alloc] initWithCapacity:kInitialNumOfWeakAccessibilityItems];

    [self checkGenericPasswordsForWeakAccessibility:weakAccessibilityItems];
    [self checkInternetPasswordsForWeakAccessibility:weakAccessibilityItems];
    [self checkCertificatesForWeakAccessibility:weakAccessibilityItems];
    [self checkKeysForWeakAccessibility:weakAccessibilityItems];
    [self checkIdentitiesForWeakAccessibility:weakAccessibilityItems];

    [keychainAnalysisResults setValue:weakAccessibilityItems forKey:kstrKeyWeakAccessibilityItems];
    
    return;
}

- (void) checkGenericPasswordsForWeakAccessibility:(NSMutableArray*)resultsArray
{
    NSArray* arrItems = [allKeychainItems objectForKey:kstrKeyGenericPasswords];
    
    [self checkForWeakAccessibility:arrItems ofType:kstrResultItemGenericPassword andAddToResults:resultsArray];
    
    return;
}

- (void) checkInternetPasswordsForWeakAccessibility:(NSMutableArray*)resultsArray
{
    NSArray* arrItems = [allKeychainItems objectForKey:kstrKeyInternetPasswords];
    
    [self checkForWeakAccessibility:arrItems ofType:kstrResultItemInternetPassword andAddToResults:resultsArray];
    
    return;
}

- (void) checkCertificatesForWeakAccessibility:(NSMutableArray*)resultsArray
{
    NSArray* arrItems = [allKeychainItems objectForKey:kstrKeyCertificates];
    
    [self checkForWeakAccessibility:arrItems ofType:kstrResultItemCertificate andAddToResults:resultsArray];
    
    return;
}

- (void) checkKeysForWeakAccessibility:(NSMutableArray*)resultsArray
{
    NSArray* arrItems = [allKeychainItems objectForKey:kstrKeyKeys];
    
    [self checkForWeakAccessibility:arrItems ofType:kstrResultItemKey andAddToResults:resultsArray];
    
    return;
}

- (void) checkIdentitiesForWeakAccessibility:(NSMutableArray*)resultsArray
{
    NSArray* arrItems = [allKeychainItems objectForKey:kstrKeyIdentities];
    
    [self checkForWeakAccessibility:arrItems ofType:kstrResultItemIdentity andAddToResults:resultsArray];
    
    return;
}

- (void)checkForWeakAccessibility:(NSArray*)arrItems ofType:(NSString*)strItemType andAddToResults:(NSMutableArray*)resultsArray
{
    for (unsigned int uiIndex = 0; uiIndex < [arrItems count]; uiIndex++)
    {
        NSDictionary *dictCurrentSecItem = [arrItems objectAtIndex:uiIndex];
        NSString* strAccessibility = [dictCurrentSecItem objectForKey:kstrKeyAccessible];
        BOOL canItemBeAccessedInsecurely = [FS_KA_Helper checkIfAccessibilityIsWeak:strAccessibility];
        
        if (NO == canItemBeAccessedInsecurely)
            continue;
        
        NSMutableDictionary *dictAnalysisResultItem = [NSMutableDictionary dictionaryWithDictionary:dictCurrentSecItem];
        [dictAnalysisResultItem setValue:strItemType forKey:kstrKeyResultItemType];
        [resultsArray addObject:dictAnalysisResultItem];
    }
    
    return;
}

#pragma mark - Export Keychain Data
- (NSString*)convertKeychainDataToJSONP
{
    NSString* strKeychainDataJSON = [FS_KA_Helper convertDictionaryToJSON:allKeychainItems];
    if (nil == strKeychainDataJSON)
        return nil;

    NSString* strKeychainDataJSONP = [FS_KA_Helper wrapJSONData:strKeychainDataJSON withFunction:kstrDataReportJSONFunction];
    if (nil == strKeychainDataJSONP)
        return nil;
    
    return strKeychainDataJSONP;
}

- (NSURL*)createDataDirectory
{
    NSURL* urlDataExportDir = [self getDataDirectory];
    if (nil == urlDataExportDir)
    {
        return nil;
    }
    
    NSError* errString;
    BOOL bSuccess = [[NSFileManager defaultManager]createDirectoryAtURL:urlDataExportDir withIntermediateDirectories:TRUE attributes:nil error:&errString];
    if (YES != bSuccess)
    {
        NSLog(@"Error occured while creating the %@ directory. Error is %@", [urlDataExportDir path], [errString localizedDescription]);
        return nil;
    }
    
    return urlDataExportDir;
}
- (NSURL*)getDataDirectory
{
    //We are using the "Cache" directory to store this file since iTunes and iCloud do NOT backup the contents of the "Cache" directory
    NSArray* arrURLs = [[NSFileManager defaultManager]URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask];
    if (0 >= [arrURLs count]) {
        NSLog(@"Could not obtain the path for user's Cache directory. Returning");
        return nil;
    }

    NSURL* urlCacheDir      = [arrURLs objectAtIndex:0];
    NSURL* urlDataExportDir = [urlCacheDir  URLByAppendingPathComponent:kstrDataAndReportsDir isDirectory:YES];
    
    return urlDataExportDir;
}

- (void)copyDataViewerHTMLToDataDirectory:(NSURL*)dataDir
{
    NSURL* dataViewerHTMLURL = [[NSBundle mainBundle] URLForResource:kstrDataReportViewerFileName withExtension:kstrDataReportViewerFileExt];
    if (nil == dataViewerHTMLURL)
    {
        NSLog(@"The iOSKeychain Data Viewer HTML file - %@.%@ does not exist.", kstrDataReportViewerFileName, kstrDataReportViewerFileExt);
    }
    else
    {
        [FS_KA_Helper copyItemAtURL:dataViewerHTMLURL toDirAtURL:dataDir];
    }
    
    NSURL* dataViewerHTMLHeaderFileURL = [[NSBundle mainBundle] URLForResource:kstrReportHeaderImageFileName withExtension:kstrReportHeaderImageFileExt];
    if (nil == dataViewerHTMLHeaderFileURL)
    {
        NSLog(@"The iOSKeychain Data Viewer HTML header image - %@.%@ does not exist.", kstrReportHeaderImageFileName,kstrReportHeaderImageFileExt);
    }
    else
    {
        [FS_KA_Helper copyItemAtURL:dataViewerHTMLHeaderFileURL toDirAtURL:dataDir];
    }
    
    return;
}

- (void)saveKeychainData:(NSString*)strKeychainDataJSONP toReportDir:(NSURL*)dataDir;
{
    NSURL* urlKeychainDataReportFile = [dataDir URLByAppendingPathComponent:kstrDataReportFile];
    
    [FS_KA_Helper saveData:strKeychainDataJSONP toFile:urlKeychainDataReportFile];
}


#pragma mark - Export Analysis Data
- (NSString*)convertstrAnalysisDataToJSONP
{
    NSString* strAnalysisDataJSON = [FS_KA_Helper convertDictionaryToJSON:keychainAnalysisResults];
    if (nil == strAnalysisDataJSON)
        return nil;
    
    NSString* strAnalysisDataJSONP = [FS_KA_Helper wrapJSONData:strAnalysisDataJSON withFunction:kstrAnalysisReportJSONFunction];
    if (nil == strAnalysisDataJSONP)
        return nil;
    
    return strAnalysisDataJSONP;
}

- (void)saveAnalysisData:(NSString*)strAnalysisDataJSONP toReportDir:(NSURL*)dataDir
{
    NSURL* urlAnalysisDataReportFile = [dataDir URLByAppendingPathComponent:kstrAnalysisReportFile];
    
    [FS_KA_Helper saveData:strAnalysisDataJSONP toFile:urlAnalysisDataReportFile];
}

- (void)copyAnalysisReportViewerHTMLToDataDirectory:(NSURL*)dataDir
{
    NSURL* analysisReportViewerHTMLURL = [[NSBundle mainBundle] URLForResource:kstrAnalysisReportViewerFileName withExtension:kstrAnalysisReportViewerFileExt];
    if (nil == analysisReportViewerHTMLURL)
    {
        NSLog(@"The iOSKeychain Analysis Report Viewer HTML file - %@.%@ does not exist.", kstrAnalysisReportViewerFileName, kstrAnalysisReportViewerFileExt);
    }
    else
    {
        [FS_KA_Helper copyItemAtURL:analysisReportViewerHTMLURL toDirAtURL:dataDir];
    }
    
    NSURL* analysisReportViewerHTMLHeaderFileURL = [[NSBundle mainBundle] URLForResource:kstrReportHeaderImageFileName withExtension:kstrReportHeaderImageFileExt];
    if (nil == analysisReportViewerHTMLHeaderFileURL)
    {
        NSLog(@"The iOSKeychain Analysis Report Viewer HTML header image - %@.%@ does not exist.", kstrReportHeaderImageFileName,kstrReportHeaderImageFileExt);
    }
    else
    {
        [FS_KA_Helper copyItemAtURL:analysisReportViewerHTMLHeaderFileURL toDirAtURL:dataDir];
    }
    
    return;
}


#pragma mark - Common Functions
- (NSArray*)searchKeychainUsingQuery:(NSDictionary*)queryParams
{
    CFArrayRef resultItems;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(queryParams), (CFTypeRef*)&resultItems);
    if(errSecSuccess != status)
    {
        if (errSecItemNotFound == status)
            NSLog(@"No keychain items found matching the specified criteria. Returning");
        else
            NSLog(@"Error encountered while enumerating keychain for the specified criteria. Error code: %ld",status);
        
        return nil;
    }
    
    NSArray *nsResults = (__bridge NSArray *)(resultItems);
    
    return nsResults;
}


- (void)addCommonAttributesFrom:(NSDictionary *)dictSecItemAttributes toDictionary:(NSMutableDictionary *)resultDictionary
{
    if(nil == dictSecItemAttributes) //nothing to add
        return;
    
    if (0 >= [dictSecItemAttributes count])
        return; //nothing to add
    
    if(nil == resultDictionary) //result dictionary is nil
        return;
    
    NSString* strAccessible =       [FS_KA_Helper getAccessiblityForSecItem:dictSecItemAttributes];
    NSString* strAccessGroup =      [FS_KA_Helper getAccessGroupForSecItem:dictSecItemAttributes];
    NSString* strCreationDate =     [FS_KA_Helper getCreationDateForSecItem:dictSecItemAttributes];
    NSString* strModificationDate = [FS_KA_Helper getModificationDateForSecItem:dictSecItemAttributes];
    NSString* strDescription =      [FS_KA_Helper getDescriptionForSecItem:dictSecItemAttributes];
    NSString* strComment =          [FS_KA_Helper getCommentForSecItem:dictSecItemAttributes];
    NSString* strCreator =          [FS_KA_Helper getCreatorForSecItem:dictSecItemAttributes];
    NSString* strType =             [FS_KA_Helper getTypeForSecItem:dictSecItemAttributes];
    NSString* strLabel =            [FS_KA_Helper getLabelForSecItem:dictSecItemAttributes];
    NSString* strIsInvisible =      [FS_KA_Helper getIsInvisibleForSecItem:dictSecItemAttributes];
    NSString* strIsNegative =       [FS_KA_Helper getIsNegativeForSecItem:dictSecItemAttributes];
    
    [resultDictionary setValue:strAccessible        forKey:kstrKeyAccessible];
    [resultDictionary setValue:strAccessGroup       forKey:kstrKeyAccessGroup];
    [resultDictionary setValue:strCreationDate      forKey:kstrKeyCreationDate];
    [resultDictionary setValue:strModificationDate  forKey:kstrKeyModificationDate];
    [resultDictionary setValue:strDescription       forKey:kstrKeyDescription];
    [resultDictionary setValue:strComment           forKey:kstrKeyComment];
    [resultDictionary setValue:strCreator           forKey:kstrKeyCreator];
    [resultDictionary setValue:strType              forKey:kstrKeyType];
    [resultDictionary setValue:strLabel             forKey:kstrKeyLabel];
    [resultDictionary setValue:strIsInvisible       forKey:kstrKeyIsInvisible];
    [resultDictionary setValue:strIsNegative        forKey:kstrKeyIsNegative];
    
    return; // Indicates Success
}

#pragma mark - Display Confirmation Dialog
- (void)launchConfirmationDialogForDataExport:(BOOL)bErrorOccured
{
    NSString* strMessage = kstrConfirmationDialogErrorMsg;
    
    if (NO == bErrorOccured)
    {
        NSURL* urlDataDir = [self getDataDirectory];
        if (nil != urlDataDir)
        {
            NSString* strKeychainExportDataFileName = kstrDataReportViewerFileName;
            NSString* strKeychainExportDataFileNameWithExtension = [strKeychainExportDataFileName stringByAppendingPathExtension:kstrDataReportViewerFileExt];
            NSURL* strKeychainExportDataFileAbsPath = [urlDataDir URLByAppendingPathComponent:strKeychainExportDataFileNameWithExtension isDirectory:NO];
            strMessage = [kstrConfirmationDialogSuccessMsg stringByAppendingString:[strKeychainExportDataFileAbsPath path]];
        }
    }
    
    [self launchConfirmationDialogWithTitle:kstrConfirmationView_ExportData andMessage:strMessage];
    
    return;
}

- (void)launchConfirmationDialogForAnalysisReport:(BOOL)bErrorOccured
{
    NSString* strMessage = kstrConfirmationDialogErrorMsg;
    
    if (NO == bErrorOccured)
    {
        NSURL* urlDataDir = [self getDataDirectory];
        if (nil != urlDataDir)
        {
            NSString* strKeychainAnalysisReportFileName = kstrAnalysisReportViewerFileName;
            NSString* strKeychainAnalysisReportFileNameWithExtension = [strKeychainAnalysisReportFileName stringByAppendingPathExtension:kstrAnalysisReportViewerFileExt];
            NSURL* strKeychainAnalysisReportFileAbsPath = [urlDataDir URLByAppendingPathComponent:strKeychainAnalysisReportFileNameWithExtension
                                                                                      isDirectory:NO];
            strMessage = [kstrConfirmationDialogSuccessMsg stringByAppendingString:[strKeychainAnalysisReportFileAbsPath path]];
        }
    }
    
    [self launchConfirmationDialogWithTitle:kstrConfirmationView_AnalyzeData andMessage:strMessage];
    
    return;
}

- (void)launchConfirmationDialogWithTitle:(NSString*)strTitle andMessage:(NSString*)strMessage
{
    FS_KA_ConfirmationDialogViewController *confirmationDialogController = [[FS_KA_ConfirmationDialogViewController alloc]
                                                                            initWithNibName:@"ConfirmationDialogView" bundle:nil];
    [confirmationDialogController setModalTransitionStyle:UIModalTransitionStyleCoverVertical];
    [confirmationDialogController setDelegate:self];
    [confirmationDialogController setStrViewTitle:strTitle];
    [confirmationDialogController setStrMessage:strMessage];
//    [self presentViewController:confirmationDialogController animated:YES completion:nil];
    
    [[self navigationController]pushViewController:confirmationDialogController animated:YES];
    
    return;
}

#pragma mark - Confirmation Dialog Delegate Protocol
- (void)confirmationDialog:(FS_KA_ConfirmationDialogViewController *)viewController closeView:(BOOL)closeButtonClicked
{
    //[self dismissViewControllerAnimated:YES completion:nil];
    
    [[self navigationController]popViewControllerAnimated:YES];
    
    return;
}

#pragma mark - About Dialog Delegate Protocol
- (void)aboutDialog:(FS_KA_AboutDialogViewController *)viewController closeView:(BOOL)closeButtonClicked
{
    [[self navigationController]popViewControllerAnimated:YES];
    
    return;
}


@end
