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
import Network
import NetworkExtension
import SwiftRuleEngine


public protocol NEFilterSocketFlowInterface: Encodable, StringSubscriptable {
    var url: URL? { get }
    var direction: NETrafficDirection { get }
    var sourceAppAuditToken: Data? { get }
    var identifier: UUID { get }

    var remoteHostname: String? { get }
    var socketFamily: Int32 { get }
    var socketType: Int32 { get }
    var socketProtocol: Int32 { get }
    var remoteIP: String? { get }
    var localIP: String? { get }
    var remotePort: Int? { get }
    var localPort: Int? { get }
}


extension NEFilterSocketFlow: @retroactive StringSubscriptable {}
extension NEFilterSocketFlow: NEFilterSocketFlowInterface {
    public var remoteIP: String? {
        if #available(macOS 15.0, *) {
            guard let remoteEndpoint = remoteFlowEndpoint else {
                return nil
            }
            if case .hostPort(let host, _) = remoteEndpoint {
                switch host {
                case .ipv4(let ip):
                    return ip.debugDescription
                case .ipv6(let ip):
                    return ip.debugDescription
                case .name(let name, _):
                    return name
                @unknown default:
                    return nil
                }
            }
            return nil
        } else {
            guard let remoteEndpoint = remoteEndpoint as? NWHostEndpoint else {
                return nil
            }
            return remoteEndpoint.hostname
        }
    }
    public var remotePort: Int? {
        if #available(macOS 15.0, *) {
            guard let remoteEndpoint = remoteFlowEndpoint else {
                return nil
            }
            if case .hostPort(_, let port) = remoteEndpoint {
                return Int(port.rawValue)
            }
            return nil
        } else {
            guard let remoteEndpoint = remoteEndpoint as? NWHostEndpoint else {
                return nil
            }
            return Int(remoteEndpoint.port)
        }
    }
    public var localIP: String? {
        if #available(macOS 15.0, *) {
            guard let localEndpoint = localFlowEndpoint else {
                return nil
            }
            if case .hostPort(let host, _) = localEndpoint {
                switch host {
                case .ipv4(let ip):
                    return ip.debugDescription
                case .ipv6(let ip):
                    return ip.debugDescription
                case .name(let name, _):
                    return name
                @unknown default:
                    return nil
                }
            }
            return nil
        } else {
            guard let localEndpoint = localEndpoint as? NWHostEndpoint else {
                return nil
            }
            return localEndpoint.hostname
        }
    }
    public var localPort: Int? {
        if #available(macOS 15.0, *) {
            guard let localEndpoint = localFlowEndpoint else {
                return nil
            }
            if case .hostPort(_, let port) = localEndpoint {
                return Int(port.rawValue)
            }
            return nil
        } else {
            guard let localEndpoint = localEndpoint as? NWHostEndpoint else {
                return nil
            }
            return Int(localEndpoint.port)
        }
    }

    static private let keys: [String: PartialKeyPath<NEFilterSocketFlow>] = [
        "url": \.url,
        "direction": \.direction.toString,
        "source_app_audit_token": \.sourceAppAuditToken,
        "identifier": \.identifier,
        "remote_ip": \.remoteIP,
        "remote_port": \.remotePort,
        "remote_hostname": \.remoteHostname,
        "local_ip": \.localIP,
        "local_port": \.localPort,
        "socket_family": \.socketFamily,
        "socket_type": \.socketType,
        "socket_protocol": \.socketProtocol
    ]

    public subscript(key: String) -> Any? {
        guard let kp = Self.keys[key] else {
            return nil
        }
        return self[keyPath: kp]
    }
}

