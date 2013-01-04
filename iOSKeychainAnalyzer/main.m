//
//  main.m
//  iOSKeychainAnalyzer
//
//  Created by Consultant on 9/9/12.
//  Copyright (c) 2012 Foundstone Inc., A Division of McAfee. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "FS_KA_AppDelegate.h"

int main(int argc, char *argv[])
{
    @autoreleasepool {
    //
    //Invoke the UIApplicationMain function
    //  - Use the default UIApplication class to manage the application.
    //      - UIApplication class will be executing the run loop dispatching events to our delegate
    //        FS_KA_AppDelegate
    //  - The remaining part of the application launch can be found in the delegate function -
    //    FS_KA_AppDelegate application:didFinishLaunchingWithOptions
    //
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([FS_KA_AppDelegate class]));
    }
}
