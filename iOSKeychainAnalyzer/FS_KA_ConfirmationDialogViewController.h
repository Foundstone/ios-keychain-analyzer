//
//  FS_KA_ConfirmationDialogViewController.h
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 10/6/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <UIKit/UIKit.h>

@protocol FS_KA_ConfirmationDialogDelegateProtocol;
@interface FS_KA_ConfirmationDialogViewController : UIViewController
{
    UINavigationItem    *uiNavItem;
}

#pragma mark - UI Events and Outlets
@property (weak, nonatomic) IBOutlet UITextView *txtMessage;
@property (weak, nonatomic) id <FS_KA_ConfirmationDialogDelegateProtocol> delegate;
@property (weak, nonatomic) NSString* strMessage;
@property (weak, nonatomic) NSString* strViewTitle;

- (IBAction)closeView:(id)sender;
@end


#pragma mark - Protocol for parent view to implement
@protocol FS_KA_ConfirmationDialogDelegateProtocol <NSObject>

- (void)    confirmationDialog:     (FS_KA_ConfirmationDialogViewController*)   viewController
                     closeView:     (BOOL)                                      closeButtonClicked;
@end

