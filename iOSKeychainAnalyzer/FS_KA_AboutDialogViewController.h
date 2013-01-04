//
//  FS_KA_AboutDialogViewController.h
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 11/24/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <UIKit/UIKit.h>

@protocol FS_KA_AboutDialogDelegateProtocol;

@interface FS_KA_AboutDialogViewController : UIViewController
{
    UINavigationItem    *uiNavItem;
}

#pragma mark - UI Events and Outlets
@property (weak, nonatomic) id <FS_KA_AboutDialogDelegateProtocol> delegate;

- (IBAction)closeView:(id)sender;

@end


#pragma mark - Protocol for parent view to implement
@protocol FS_KA_AboutDialogDelegateProtocol <NSObject>

- (void)    aboutDialog:     (FS_KA_AboutDialogViewController*)   viewController
              closeView:     (BOOL)                               closeButtonClicked;
@end

