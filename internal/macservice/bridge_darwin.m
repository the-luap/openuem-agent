//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include "bridge_darwin.h"

void *openuem_app_service_open(const char *bundle_path, const char *executable_path,
                             const char *identifier, const char *plist_name) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            NSBundle *bundle = [NSBundle mainBundle];
            if (![bundle.bundlePath isEqualToString:[NSString stringWithUTF8String:bundle_path]] ||
                ![bundle.executablePath isEqualToString:[NSString stringWithUTF8String:executable_path]] ||
                ![bundle.bundleIdentifier isEqualToString:[NSString stringWithUTF8String:identifier]]) return NULL;
            SMAppService *service = [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:plist_name]];
            return (void *)[service retain];
        }
        return NULL;
    }
}

int openuem_app_service_status(void *opaque) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            if (opaque == NULL) return -1;
            switch ([(SMAppService *)opaque status]) {
                case SMAppServiceStatusNotRegistered: return 0;
                case SMAppServiceStatusEnabled: return 1;
                case SMAppServiceStatusRequiresApproval: return 2;
                case SMAppServiceStatusNotFound: return 3;
                default: return -1;
            }
        }
        return -1;
    }
}

int openuem_app_service_register(void *opaque) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            if (opaque == NULL) return 0;
            NSError *error = nil;
            return [(SMAppService *)opaque registerAndReturnError:&error] ? 1 : 0;
        }
        return 0;
    }
}

void openuem_app_service_close(void *opaque) {
    @autoreleasepool { if (opaque != NULL) [(NSObject *)opaque release]; }
}
