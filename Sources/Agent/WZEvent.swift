// Copyright 2025 Santiago Alvarez.
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

import Foundation
import EndpointSecurity
import NetworkExtension
import SwiftRuleEngine
import OSLog


@StringSubscriptable(withKeys: false)
public struct WZEvent {
    public let timestamp: Double
    public let machTime: UInt64
    public var process: WZProcess?
    public let payload: any WZEventPayload
    public let eventType: WZEventType
    public let eventClass: WZEventClass
    public var seqNum: UInt64?
    public var globalSeqNum: UInt64?

    private static let keys: [String: PartialKeyPath<WZEvent>] = [
        "timestamp": \.timestamp,
        "mach_time": \.machTime,
        "process": \.process,
        "payload": \.payload,
        "event_type": \.eventType.rawValue,
        "event_class": \.eventClass.rawValue,
    ]
}

extension WZEvent {
    public init?(_ msg: UnsafePointer<es_message_t>,
          processTree: WZProcessTree=WZProcessTree.shared) {
        self.machTime = WZUtils.machTimeToNanoseconds(machTime: msg.pointee.mach_time)
        self.timestamp = msg.pointee.time.seconds
        self.eventType = WZEventType(msg.pointee.event_type)
        self.eventClass = .es
        self.seqNum = msg.pointee.seq_num
        self.globalSeqNum = msg.pointee.global_seq_num

        if let cachedProcess = processTree.get(msg.pointee.process.pointee.audit_token.key) {
            self.process = cachedProcess
        } else {
            self.process = WZProcess(proc: msg.pointee.process.pointee, isExecParent: true)
        }

        switch self.eventType {
        case .es_exec:
            payload = WZExecPayload(msg.pointee.event.exec)

        case .es_fork:
            payload = WZForkPayload(msg.pointee.event.fork)

        case .es_mount:
            payload = WZMountPayload(msg.pointee.event.mount)

        case .es_unmount:
            payload = WZUnmountPayload(msg.pointee.event.unmount)

        case .es_remount:
            payload = WZRemountPayload(msg.pointee.event.remount)


        case .es_exit:
            payload = WZExitPayload(msg.pointee.event.exit)

        case .es_cs_invalidated:
            payload = WZCSInvalidatedPayload()

        case .es_xp_malware_detected:
            payload = WZXPMalwareDetectedPayload(msg.pointee.event.xp_malware_detected)

        case .es_xp_malware_remediated:
            payload = WZXPMalwareRemediatedPayload(msg.pointee.event.xp_malware_remediated)

        case .es_login:
            payload = WZLoginPayload(msg.pointee.event.login_login)

        case .es_logout:
            payload = WZLogoutPayload(msg.pointee.event.login_logout)

        case .es_screensharing_attach:
            payload = WZScreenSharingAttachPayload(msg.pointee.event.screensharing_attach)

        case .es_screensharing_detach:
            payload = WZScreenSharingDetachPayload(msg.pointee.event.screensharing_detach)

        case .es_btm_launch_item_add:
            payload = WZBTMLaunchItemAddPayload(msg.pointee.event.btm_launch_item_add.pointee)

        case .es_btm_launch_item_remove:
            payload = WZBTMLaunchItemRemovePayload(msg.pointee.event.btm_launch_item_remove.pointee)

        default:
            return nil
        }
    }

    public init(_ flow: any NEFilterSocketFlowInterface, _ timestamp: Double,
         processTree: WZProcessTree=WZProcessTree.shared) {
        self.machTime = WZUtils.machTimeToNanoseconds(machTime: mach_absolute_time())
        self.timestamp = timestamp
        self.eventClass = .ne

        switch flow.direction {
        case .inbound:
            self.eventType = .ne_inbound
            self.payload = WZInboundPayload(flow)
        default:
            self.eventType = .ne_outbound
            self.payload = WZOutboundPayload(flow)
        }

        guard let auditTokenData = flow.sourceAppAuditToken,
              let auditToken = audit_token_t(data: auditTokenData) else {
            return
        }

        self.process = processTree.get(auditToken.key)
        if self.process == nil {
            self.process = WZProcess(auditToken: auditToken)
        }
    }

    /// Initializer for dns
    public init(_ flow: any NEFilterSocketFlowInterface, _ timestamp: Double,
         _ dnsReply: Data, processTree: WZProcessTree=WZProcessTree.shared) {
        self.machTime = WZUtils.machTimeToNanoseconds(machTime: mach_absolute_time())
        self.eventClass = .ne
        self.payload = WZDNSReplyPayload(flow, dnsReply)
        self.timestamp = timestamp
        self.eventType = .ne_dns_reply

        guard let auditTokenData = flow.sourceAppAuditToken,
              let auditToken = audit_token_t(data: auditTokenData) else {
            return
        }

        self.process = processTree.get(auditToken.key)
        if self.process == nil {
            self.process = WZProcess(auditToken: auditToken)
        }
    }
}

extension WZEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(timestamp, forKey: .timestamp)

        try container.encode(payload, forKey: .payload)
        try self.process?.encodeWithParent(to: container.superEncoder(forKey: .process))
        try container.encode(eventType, forKey: .eventType)
        try container.encode(eventClass, forKey: .eventClass)
        try container.encode(seqNum, forKey: .seqNum)
        try container.encode(globalSeqNum, forKey: .globalSeqNum)
    }

    enum CodingKeys: String, CodingKey {
        case timestamp, process, payload, eventType,
             seqNum, globalSeqNum, eventClass, machTime
    }
}
