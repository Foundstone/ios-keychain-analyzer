//
//  FS_KA_ConfirmationDialogViewController.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 10/6/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import "FS_KA_ConfirmationDialogViewController.h"

@interface FS_KA_ConfirmationDialogViewController ()

@end

@implementation FS_KA_ConfirmationDialogViewController
@synthesize txtMessage;
@synthesize delegate;
@synthesize strMessage;
@synthesize strViewTitle;

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
    [txtMessage setText:strMessage];
}

- (void)viewDidUnload
{
    [self setTxtMessage:nil];
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
        [uiNavItem setTitle:strViewTitle];
        [uiNavItem setHidesBackButton:YES];
    }
    
    return uiNavItem;
}

- (IBAction)closeView:(id)sender
{
    [[self delegate]confirmationDialog:self closeView:YES];
    
    return;
}

@end
