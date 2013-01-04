//
//  FS_KA_AboutDialogViewController.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 11/24/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import "FS_KA_AboutDialogViewController.h"

@interface FS_KA_AboutDialogViewController ()

@end

@implementation FS_KA_AboutDialogViewController
@synthesize delegate;

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
        [uiNavItem setTitle:@"About"];
        [uiNavItem setHidesBackButton:YES];
    }
    
    return uiNavItem;
}

- (IBAction)closeView:(id)sender
{
    [[self delegate]aboutDialog:self closeView:YES];
    
    return;
}

@end
