//
// Copyright © 2025 Santiago Alvarez. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import Foundation
import NetworkExtension
import SwiftRuleEngine
import Agent


@StringSubscriptable(withKeys: false)
public class NEFilterSocketFlowMock: NEFilterSocketFlowInterface {
    public var url: URL?
    public var direction: NETrafficDirection
    public var sourceAppAuditToken: Data?
    public var identifier: UUID
    public var remoteHostname: String?
    public var socketFamily: Int32
    public var socketType: Int32
    public var socketProtocol: Int32

    public var remoteIP: String?
    public var remotePort: Int?
    public var localIP: String?
    public var localPort: Int?

    private static let keys: [String: PartialKeyPath<NEFilterSocketFlowMock>] = [
        "url": \.url?.path,
        "direction": \.direction.toString,
        "source_app_audit_token": \.sourceAppAuditToken,
        "identifier": \.identifier.uuidString,
        "remote_ip": \.remoteIP,
        "remote_port": \.remotePort,
        "remote_hostname": \.remoteHostname,
        "local_ip": \.localIP,
        "local_port": \.localPort,
        "socket_family": \.socketFamily,
        "socket_type": \.socketType,
        "socket_protocol": \.socketProtocol
    ]

    public init(url: URL?, direction: NETrafficDirection, sourceAppAuditToken: Data?,
         remoteIP: String?, remotePort: Int, localIP: String?, localPort: Int,
         identifier: UUID, remoteHostname: String?,
         socketFamily: Int32, socketType: Int32, socketProtocol: Int32) {
        self.url = url
        self.direction = direction
        self.sourceAppAuditToken = sourceAppAuditToken
        self.identifier = identifier
        self.remoteHostname = remoteHostname
        self.socketFamily = socketFamily
        self.socketType = socketType
        self.socketProtocol = socketProtocol
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.localIP = localIP
        self.localPort = localPort
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.remoteIP, forKey: .remoteIp)
        try container.encode(self.remotePort, forKey: .remotePort)
        try container.encode(self.localIP, forKey: .localIp)
        try container.encode(localPort, forKey: .localPort)
        try container.encode(self.direction == .inbound ? "inbound": "outbound", forKey: .direction)
        try container.encode(self.socketFamily, forKey: .socketFamily)
        try container.encode(self.socketType, forKey: .socketType)
        try container.encode(self.socketProtocol, forKey: .socketProtocol)
        try container.encode(self.remoteHostname, forKey: .remoteHostname)
    }

    enum CodingKeys: String, CodingKey {
        case remoteIp, remotePort, localIp, localPort, direction,
             socketFamily, socketType, socketProtocol, remoteHostname
    }
}