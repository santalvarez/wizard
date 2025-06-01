//
//  Extensions.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import CryptoKit
import OSLog
import EndpointSecurity
import NetworkExtension


extension timespec {
    var seconds: Double {
        return Double(self.tv_sec) + Double(self.tv_nsec) / Double(NSEC_PER_SEC)
    }
}

extension es_token_t {
    var description: String {
        if self.data != nil && self.size > 0 {
            return String(cString: self.data)
        }
        return ""
    }
}

extension Logger {
    static let subsystem = "com.santalvarez.wizard.Agent"
    static let Agent = Logger(subsystem: subsystem, category: "default")
}

extension Encodable {
    func toDict(_ encoder: WZEncoder=WZEncoder.shared) -> [String: Any] {
        // SR-5501: https://bugs.swift.org/browse/SR-5501
        autoreleasepool {
            guard let data = try? encoder.encode(self),
                let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                return [:]
            }
            return json
        }
    }
}

extension UserDefaults {
    static var shared: UserDefaults {
        return UserDefaults(suiteName: APP_GROUP_ID)!
    }
}


internal extension in_addr {

    var description: String {

        var mutableSelf = self
        let addressLength = Int(INET_ADDRSTRLEN)
        let stringBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: addressLength)
        defer {
            stringBuffer.deallocate()
        }

        guard inet_ntop(AF_INET, &mutableSelf.s_addr, stringBuffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return "<invalid IPv4 address>"
        }

        return String(cString: stringBuffer)
    }

}

internal extension in6_addr {

    var description: String {

        var mutableSelf = self
        let addressLength = Int(INET6_ADDRSTRLEN)
        let stringBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: addressLength)
        defer {
            stringBuffer.deallocate()
        }

        guard inet_ntop(AF_INET6, &mutableSelf, stringBuffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return "<invalid IPv6 address>"
        }

        return String(cString: stringBuffer)
    }


}

extension es_string_token_t {
    var description: String {
        if self.data != nil && self.length > 0 {
            return String(cString: self.data)
        }
        return ""
    }

}

extension NEFilterSocketFlow: Encodable {
    public func encode(to encoder: Encoder) throws {
        let remoteEndpoint = self.remoteEndpoint as? NWHostEndpoint
        let localEndpoint = self.localEndpoint as? NWHostEndpoint

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(remoteEndpoint?.hostname, forKey: .remoteIp)
        try container.encode(remoteEndpoint?.port, forKey: .remotePort)
        try container.encode(localEndpoint?.hostname, forKey: .localIp)
        try container.encode(localEndpoint?.port, forKey: .localPort)
        try container.encode(self.direction == .inbound ? "inbound": "outbound", forKey: .direction)
        try container.encode(self.socketFamily, forKey: .socketFamily)
        try container.encode(self.socketType, forKey: .socketType)
        try container.encode(self.socketProtocol, forKey: .socketProtocol)
        try container.encode(remoteHostname, forKey: .remoteHostname)
    }

    enum CodingKeys: String, CodingKey {
        case remoteIp, remotePort, localIp, localPort, direction,
             socketFamily, socketType, socketProtocol, remoteHostname
    }
}

extension DateFormatter {
    static func toLocaleString(_ timestamp: Int) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        return DateFormatter.localizedString(from: date, dateStyle: .medium, timeStyle: .medium)
    }
}

extension es_destination_type_t {
    var toString: String {
        return (self == ES_DESTINATION_TYPE_EXISTING_FILE) ? "exists": "new"
    }
}

extension NETrafficDirection {
    var toString: String {
        switch self {
        case .inbound:
            return "inbound"
        case .outbound:
            return "outbound"
        case .any:
            return "any"
        @unknown default:
            return "unknown"
        }
    }
}
