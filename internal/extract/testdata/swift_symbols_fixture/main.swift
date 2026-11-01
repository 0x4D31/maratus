import Foundation

struct BenignInventory {
    static func operatingSystemDescription() -> String {
        ProcessInfo.processInfo.operatingSystemVersionString
    }
}

print(BenignInventory.operatingSystemDescription())
