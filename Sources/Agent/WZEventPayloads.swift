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
import EndpointSecurity
import NetworkExtension
import SwiftRuleEngine


public protocol WZEventPayload: Encodable, StringSubscriptable {
}


@StringSubscriptable
public struct WZExecPayload: WZEventPayload {
    public let process: WZProcess
    public let cwd: String
    public let script: String?
}

extension WZExecPayload {
    public init(_ event: es_event_exec_t) {
        self.process = WZProcess(proc: event.target.pointee)
        self.cwd = event.cwd.pointee.path.description
        self.script = event.script?.pointee.path.description

        #if DEBUG
        #else
        withUnsafePointer(to: event) { p in
            var envs: [String: String] = [:]
            let envCount = es_exec_env_count(p)
            if envCount == 0 { return }
            for i in 0...envCount-1 {
                let env = es_exec_env(p, i)
                // env is a string with the format "key=value", so we split it
                let envSplit = env.description.split(separator: "=")
                if envSplit.count != 2 { continue }
                envs[String(envSplit[0])] = String(envSplit[1])
            }
            self.process.env = envs
        }
        #endif
    }
}

@StringSubscriptable
public struct WZForkPayload: WZEventPayload {
    public let process: WZProcess
}

extension WZForkPayload {
    public init(_ event: es_event_fork_t) {
        self.process = WZProcess(proc: event.child.pointee)
    }
}

@StringSubscriptable
public struct WZExitPayload: WZEventPayload {
    public let stat: Int32
}

extension WZExitPayload {
    public init(_ event: es_event_exit_t) {
        self.stat = event.stat
    }
}

@StringSubscriptable
public struct WZMountPayload: WZEventPayload {
    public let statfs: statfs

    public init(_ event: es_event_mount_t) {
        self.statfs = event.statfs.pointee
    }
}

@StringSubscriptable
public struct WZUnmountPayload: WZEventPayload {
    public let statfs: statfs

    public init(_ event: es_event_unmount_t) {
        self.statfs = event.statfs.pointee
    }
}

@StringSubscriptable
public struct WZRemountPayload: WZEventPayload {
    public let statfs: statfs

    public init(_ event: es_event_remount_t) {
        self.statfs = event.statfs.pointee
    }
}

@StringSubscriptable(withKeys: false)
public struct WZCSInvalidatedPayload: WZEventPayload {
    static private let keys: [String: PartialKeyPath<Self>] = [:]
}


@StringSubscriptable
public struct WZXPMalwareDetectedPayload: WZEventPayload {
    public let detectedPath: String
    public let incidentIdentifier: String
    public let malwareIdentifier: String
    public let signatureVersion: String

    public init(_ event: UnsafeMutablePointer<es_event_xp_malware_detected_t>) {
        self.detectedPath = event.pointee.detected_path.description
        self.incidentIdentifier = event.pointee.incident_identifier.description
        self.malwareIdentifier = event.pointee.malware_identifier.description
        self.signatureVersion = event.pointee.signature_version.description
    }
}

@StringSubscriptable
public struct WZXPMalwareRemediatedPayload: WZEventPayload {
    public let signatureVersion: String
    public let success: Bool
    public let incidentIdentifier: String
    public let actionType: String
    public let malwareIdentifier: String
    public let resultDescription: String
    public let remediatedPath: String
    public let remediatedProcess: WZProcess?

    public init(_ event: UnsafeMutablePointer<es_event_xp_malware_remediated_t>) {
        self.signatureVersion = event.pointee.signature_version.description
        self.success = event.pointee.success
        self.incidentIdentifier = event.pointee.incident_identifier.description
        self.actionType = event.pointee.action_type.description
        self.malwareIdentifier = event.pointee.malware_identifier.description
        self.resultDescription = event.pointee.result_description.description
        self.remediatedPath = event.pointee.remediated_path.description
        if let remediatedAuditToken = event.pointee.remediated_process_audit_token {
            self.remediatedProcess = WZProcess(auditToken: remediatedAuditToken.pointee)
        } else {
            self.remediatedProcess = nil
        }
    }
}

@StringSubscriptable
public struct WZLoginPayload: WZEventPayload {
    public let success: Bool
    public let username: String
    public let uid: uid_t?
    public let failureMessage: String

    public init(_ event: UnsafeMutablePointer<es_event_login_login_t>) {
        self.success = event.pointee.success
        self.username = event.pointee.username.description
        self.failureMessage = event.pointee.failure_message.description
        self.uid = event.pointee.has_uid ? event.pointee.uid.uid : nil
    }
}

@StringSubscriptable
public struct WZLogoutPayload: WZEventPayload {
    public let uid: uid_t
    public let username: String

    public init(_ event: UnsafeMutablePointer<es_event_login_logout_t>) {
        self.uid = event.pointee.uid
        self.username = event.pointee.username.description
    }
}

@StringSubscriptable
public struct WZScreenSharingAttachPayload: WZEventPayload {
    public let success: Bool
    public let sourceAddress: String
    public let sourceAddressType: String
    public let viewerAppleID: String
    public let authenticationType: String
    public let authenticationUsername: String
    public let sessionUsername: String
    public let existingSession: Bool
    public let graphicalSessionID: UInt32

    public init(_ event: UnsafeMutablePointer<es_event_screensharing_attach_t>) {
        self.success = event.pointee.success
        self.sourceAddress = event.pointee.source_address.description
        self.viewerAppleID = event.pointee.viewer_appleid.description
        self.authenticationType = event.pointee.authentication_type.description
        self.authenticationUsername = event.pointee.authentication_username.description
        self.sessionUsername = event.pointee.session_username.description
        self.existingSession = event.pointee.existing_session
        self.graphicalSessionID = event.pointee.graphical_session_id
        switch event.pointee.source_address_type {
        case ES_ADDRESS_TYPE_NONE:
            self.sourceAddressType = "none"
        case ES_ADDRESS_TYPE_IPV4:
            self.sourceAddressType = "ipv4"
        case ES_ADDRESS_TYPE_IPV6:
            self.sourceAddressType = "ipv6"
        case ES_ADDRESS_TYPE_NAMED_SOCKET:
            self.sourceAddressType = "named_socket"
        default:
            self.sourceAddressType = "unknown"
        }
    }
}

@StringSubscriptable
public struct WZScreenSharingDetachPayload: WZEventPayload {
    public let viewerAppleID: String
    public let sourceAddress: String
    public let sourceAddressType: String
    public let graphicalSessionID: UInt32

    public init(_ event: UnsafeMutablePointer<es_event_screensharing_detach_t>) {
        self.viewerAppleID = event.pointee.viewer_appleid.description
        self.sourceAddress = event.pointee.source_address.description
        self.graphicalSessionID = event.pointee.graphical_session_id
        switch event.pointee.source_address_type {
        case ES_ADDRESS_TYPE_NONE:
            self.sourceAddressType = "none"
        case ES_ADDRESS_TYPE_IPV4:
            self.sourceAddressType = "ipv4"
        case ES_ADDRESS_TYPE_IPV6:
            self.sourceAddressType = "ipv6"
        case ES_ADDRESS_TYPE_NAMED_SOCKET:
            self.sourceAddressType = "named_socket"
        default:
            self.sourceAddressType = "unknown"
        }
    }
}

@StringSubscriptable
public struct WZBTMLaunchItemAddPayload: WZEventPayload {
    public let executablePath: String
    public let item: es_btm_launch_item_t
    public let instigator: WZProcess?
    public let app: WZProcess?

    public init(_ event: es_event_btm_launch_item_add_t) {
        self.executablePath = event.executable_path.description
        self.item = event.item.pointee
        if let inst = event.instigator?.pointee {
            self.instigator = WZProcess(proc: inst)
        } else {
            self.instigator = nil
        }
        if let app = event.app?.pointee {
            self.app = WZProcess(proc: app)
        } else {
            self.app = nil
        }
    }
}

@StringSubscriptable
public struct WZBTMLaunchItemRemovePayload: WZEventPayload {
    public let item: es_btm_launch_item_t
    public let instigator: WZProcess?
    public let app: WZProcess?

    public init(_ event: es_event_btm_launch_item_remove_t) {
        self.item = event.item.pointee
        if let inst = event.instigator?.pointee {
            self.instigator = WZProcess(proc: inst)
        } else {
            self.instigator = nil
        }
        if let app = event.app?.pointee {
            self.app = WZProcess(proc: app)
        } else {
            self.app = nil
        }
    }
}

@StringSubscriptable
public struct WZInboundPayload: WZEventPayload {
    public let flow: any NEFilterSocketFlowInterface

    public init(_ flow: any NEFilterSocketFlowInterface) {
        self.flow = flow
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.flow, forKey: .flow)
    }

    enum CodingKeys: String, CodingKey {
        case flow
    }
}

@StringSubscriptable
public struct WZOutboundPayload: WZEventPayload {
    public let flow: any NEFilterSocketFlowInterface
    public let url: String?

    public init(_ flow: any NEFilterSocketFlowInterface) {
        self.flow = flow
        self.url = flow.url?.path
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.flow, forKey: .flow)
        try container.encode(self.url, forKey: .url)
    }

    enum CodingKeys: String, CodingKey {
        case flow, url
    }
}

@StringSubscriptable
public class WZDNSReplyPayload: WZEventPayload {
    public let flow: any NEFilterSocketFlowInterface
    public let dnsReply: WZDNSReply?

    public init(_ flow: any NEFilterSocketFlowInterface, _ dnsReplyData: Data, fileCache: WZFileCache = WZFileCache.shared) {
        self.flow = flow
        var dnsReplyData = dnsReplyData

        if flow.socketProtocol == IPPROTO_TCP, let unframedData = Self.dnsUnframer(dnsReplyData) {
            dnsReplyData = unframedData
        }

        if let rawReply: UnsafeMutablePointer<dns_reply_t> = dnsReplyData.withUnsafeBytes({ buf in
            guard let base = buf.baseAddress?.assumingMemoryBound(to: Int8.self) else { return nil }
            return dns_parse_packet(base, UInt32(buf.count))
        }) {
            self.dnsReply = WZDNSReply(rawReply)
            dns_free_reply(rawReply)
        } else {
            self.dnsReply = nil
        }
    }

    private static func dnsUnframer(_ dnsReplyData: Data) -> Data? {
        guard dnsReplyData.count >= 2 else { return nil }
        let length16 = dnsReplyData.prefix(2).reduce(0) { soFar, next in (soFar << 8) | UInt16(next) }
        let messageCount = Int(length16)
        let frameCount = Int(2 + messageCount)
        guard dnsReplyData.count >= frameCount else { return nil }
        return dnsReplyData.dropFirst(2).prefix(messageCount)
    }

    private static func dnsFramer(_ dnsReplyData: Data) -> Data? {
        guard let count16 = UInt16(exactly: dnsReplyData.count) else {
            return nil
        }
        let header = (0..<2).reversed().map { UInt8((count16 >> ($0 * 8)) & 0xff) }
        return header + dnsReplyData
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.flow, forKey: .flow)
        try container.encode(self.dnsReply, forKey: .dnsReply)
    }

    enum CodingKeys: String, CodingKey {
        case flow, dnsReply
    }

}
