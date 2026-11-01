#import <Foundation/Foundation.h>

int main(void) {
    @autoreleasepool {
        NSData *data = [NSData dataWithContentsOfFile:@"~/.ssh/id_rsa"];
        return data == nil;
    }
}
