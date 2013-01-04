//
//  FS_KA_MainViewController.h
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/10/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "FS_KA_ConfirmationDialogViewController.h"
#import "FS_KA_AboutDialogViewController.h"

@interface FS_KA_MainViewController : UIViewController <FS_KA_ConfirmationDialogDelegateProtocol, FS_KA_AboutDialogDelegateProtocol>
{
    UINavigationItem    *uiNavItem;
    BOOL                bIsKeychainLoaded;
    NSMutableDictionary *allKeychainItems;
    NSMutableDictionary *keychainAnalysisResults;
}

#pragma mark - UI Events
- (IBAction)exportKeychainData: (id)sender;	
- (IBAction)analyzeKeychainData:(id)sender;
- (IBAction)aboutKeychainAnalyzer:(id)sender;

#pragma mark - Top Level Functions
- (void)            loadKeychain;
- (void)            runKeychainAnalysis;

#pragma mark - Load Generic Passwords
- (void)            loadGenericPasswords;
- (NSDictionary*)   createKeychainQueryForGenericPasswords;
- (void)            addGenericPasswords:                        (NSArray*               )resultItems;
- (void)            addGenericPasswordAttributesFrom:           (NSDictionary*          )dictSecItemAttributes
                                        toDictionary:           (NSMutableDictionary*   )resultDictionary;

#pragma mark - Load Internet Passwords
- (void)            loadInternetPasswords;
- (NSDictionary*)   createKeychainQueryForInternetPasswords;
- (void)            addInternetPasswords:                       (NSArray*               )resultItems;
- (void)            addInternetPasswordAttributesFrom:          (NSDictionary *         )dictSecItemAttributes
                                         toDictionary:          (NSMutableDictionary*   )resultDictionary;

#pragma mark - Load Certificates
- (void)            loadCertificates;
- (NSDictionary*)   createKeychainQueryForCertificates;
- (void)            addCertificates:                            (NSArray*               )resultItems;
- (void)            addCertificateAttributesFrom:               (NSDictionary*          )dictSecItemAttributes
                                    toDictionary:               (NSMutableDictionary*   )resultDictionary;
- (void)            addCertificateSummaryForCertificateFrom:    (NSDictionary*          )dictSecItemAttributes
                                               toDictionary:    (NSMutableDictionary*   )resultDictionary;

#pragma mark - Load Keys
- (void)            loadKeys;
- (NSDictionary*)   createKeychainQueryForKeys;
- (void)            addKeys:                                    (NSArray*               )resultItems;
- (void)            addKeyAttributesFrom:                       (NSDictionary*          )dictSecItemAttributes
                            toDictionary:                       (NSMutableDictionary *  )resultDictionary;
#pragma mark - Load Identities
- (void)            loadIdentities;
- (NSDictionary*)   createKeychainQueryForIdentities;
- (void)            addIdentities:                              (NSArray*               )resultItems;
- (void)            addCertificateSummaryForIdentityFrom:       (NSDictionary*          )dictSecItemAttributes
                                            toDictionary:       (NSMutableDictionary*   )resultDictionary;
#pragma mark - Export Keychain Data
- (NSString*)       convertKeychainDataToJSONP;
- (NSURL*)          createDataDirectory;
- (NSURL*)          getDataDirectory;
- (void)            copyDataViewerHTMLToDataDirectory:          (NSURL*                 )dataDir;
- (void)            saveKeychainData:                           (NSString*              )strKeychainDataJSONP
                         toReportDir:                           (NSURL*                 )dataDir;
#pragma mark - Export Analysis Data
- (NSString*)       convertstrAnalysisDataToJSONP;
- (void)            copyAnalysisReportViewerHTMLToDataDirectory:(NSURL*                 )dataDir;
- (void)            saveAnalysisData:                           (NSString*              )strAnalysisDataJSONP
                         toReportDir:                           (NSURL*                 )dataDir;

#pragma mark Analysis - Check for weak passwords
- (void)            checkKeychainItemsForWeakPasswords;
- (void)            checkGenericPasswordsForWeakPasswords:      (NSMutableArray*        )resultsArray;
- (void)            checkInternetPasswordsForWeakPasswords:     (NSMutableArray*        )resultsArray;
- (void)            checkForWeakPasswords:                      (NSArray*               )arrPasswords
                                   ofType:                      (NSString*              )strPasswordType
                          andAddToResults:                      (NSMutableArray*        )resultsArray;

#pragma mark Analysis - Check for weak authentication scheme
- (void)            checkKeychainItemsForWeakAuthScheme;
- (void)            checkInternetPasswordsForWeakAuthScheme:    (NSMutableArray*        )weakAuthSchemeItems;

#pragma mark Analysis - Check for weak protocols
- (void)            checkKeychainItemsForWeakProtocols;
- (void)            checkInternetPasswordsForWeakProtocols:     (NSMutableArray*        )resultsArray;

#pragma mark - Common Functions
- (NSArray*)        searchKeychainUsingQuery:                   (NSDictionary*          )queryParams;
- (void)            addCommonAttributesFrom:                    (NSDictionary*          )dictSecItemAttributes
                               toDictionary:                    (NSMutableDictionary*   )resultDictionary;

#pragma mark Analysis - Check for weak keys
- (void)            checkKeychainItemsForWeakKeys;
- (void)            checkKeysForWeakKeys:                       (NSMutableArray*        )resultsArray;
- (void)            checkIdentitiesForWeakKeys:                 (NSMutableArray*        )resultsArray;
- (void)            checkForWeakKeys:                           (NSArray*               )arrItems
                              ofType:                           (NSString*              )strItemType
                     andAddToResults:                           (NSMutableArray*        )resultsArray;

#pragma mark Analysis - Check for weak accessibility
- (void)            checkKeychainItemsForInsecureAccessibility;
- (void)            checkGenericPasswordsForWeakAccessibility:  (NSMutableArray*        )resultsArray;
- (void)            checkInternetPasswordsForWeakAccessibility: (NSMutableArray*        )resultsArray;
- (void)            checkCertificatesForWeakAccessibility:      (NSMutableArray*        )resultsArray;
- (void)            checkKeysForWeakAccessibility:              (NSMutableArray*        )resultsArray;
- (void)            checkIdentitiesForWeakAccessibility:        (NSMutableArray*        )resultsArray;
- (void)            checkForWeakAccessibility:                  (NSArray*               )arrItems
                                       ofType:                  (NSString*              )strItemType
                              andAddToResults:                  (NSMutableArray*        )resultsArray;

#pragma mark - Display Confirmation Dialog
- (void)            launchConfirmationDialogForDataExport:      (BOOL                   )bErrorOccured;
- (void)            launchConfirmationDialogForAnalysisReport:  (BOOL                   )bErrorOccured;
- (void)            launchConfirmationDialogWithTitle:          (NSString*              )strTitle
                                           andMessage:          (NSString*              )strMessage;





@end
