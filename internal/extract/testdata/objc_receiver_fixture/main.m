#import <Foundation/Foundation.h>

int main(void) {
    @autoreleasepool {
        NSTask *task = [[NSTask alloc] init];
        task.launchPath = @"/usr/bin/true";
        task.arguments = @[@"--version", @"fixture-value"];
        [task launch];
    }
    return 0;
}
