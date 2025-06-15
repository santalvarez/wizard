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
@testable import Agent


extension audit_token_t {
    static func build(pid: UInt32, pidVersion: UInt32) -> audit_token_t {
        audit_token_t(val: (0, 123, 123, 123,
                            123, pid, 0, pidVersion))
    }

    static func buildRandom() -> audit_token_t {
        audit_token_t(val: (0, 123, 123, 123,
                            123, UInt32.random(in: 0..<65000),
                            0, UInt32.random(in: 0..<65000)))
    }
}

extension WZFile {
    static func buildRandom() -> WZFile {
        return WZFile(path: generateRandomPath(numFolders: 3),
                      pathTruncated: false,
                      name: String.shuffeld(length: 10)!)
    }
}

extension WZProcess {
    static func build(parentAuditToken: audit_token_t? = nil) -> WZProcess {
        let parentToken = (parentAuditToken != nil) ? parentAuditToken! : audit_token_t.buildRandom()
        return WZProcess(file: WZFile.buildRandom(),
                         auditToken: audit_token_t.buildRandom(),
                         parentAuditToken: parentToken)
    }

    static func build(parentAuditToken: audit_token_t,
                      pid: UInt32, pidVersion: UInt32) -> WZProcess {
        return WZProcess(file: WZFile.buildRandom(),
                         auditToken: audit_token_t.build(pid: pid,
                                                         pidVersion: pidVersion),
                         parentAuditToken: parentAuditToken)
    }

    static func buildRandom() -> WZProcess {
        return WZProcess(file: WZFile.buildRandom(),
                         auditToken: audit_token_t.buildRandom(),
                         parentAuditToken: audit_token_t.buildRandom())
    }
}

extension NEFilterSocketFlowMock {
    static func buildRandomInbound() -> NEFilterSocketFlowMock {
        return NEFilterSocketFlowMock(url: nil, direction: .inbound, sourceAppAuditToken: nil, remoteIP: "192.168.0.40",
                                      remotePort: 123, localIP: "192.168.0.35", localPort: 234, identifier: .init(),
                                      remoteHostname: nil, socketFamily: 1, socketType: 1, socketProtocol: IPPROTO_TCP)
    }
}


extension WZEvent {
    static func buildRandomExec() -> WZEvent {
        let process = WZProcess.buildRandom()
        let child = WZProcess.build(parentAuditToken: process.auditToken,
                                    pid: UInt32(process.pid),
                                    pidVersion: UInt32(process.pidVersion+1))
        let payload = WZExecPayload(process: child, cwd: "", script: nil)
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: WZUtils.machTimeToNanoseconds(machTime: mach_absolute_time()),
                       process: process, payload: payload, eventType: .es_exec,
                       eventClass: .es, seqNum: 1, globalSeqNum: 1)
    }

    static func buildRandomInbound() -> WZEvent {
        let process = WZProcess.buildRandom()
        let payload = WZInboundPayload(NEFilterSocketFlowMock.buildRandomInbound())
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: WZUtils.machTimeToNanoseconds(machTime: mach_absolute_time()),
                       process: process, payload: payload, eventType: .ne_inbound,
                       eventClass: .es, seqNum: 1, globalSeqNum: 1)
    }


    static func buildExecEvent(with machTime: UInt64, with process: WZProcess) -> WZEvent {
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: machTime,
                       process: process,
                       payload: WZExecPayload(process: WZProcess.build(parentAuditToken: process.parentAuditToken,
                                                                     pid: UInt32(process.pid),
                                                                     pidVersion: UInt32(process.pidVersion)+1),
                                            cwd: "", script: nil),
                       eventType: .es_exec, eventClass: .es)
    }

    static func buildForkEvent(with machTime: UInt64, with process: WZProcess) -> WZEvent {
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: machTime,
                       process: process,
                       payload: WZForkPayload(process: WZProcess.build(parentAuditToken: process.auditToken)),
                       eventType: .es_fork, eventClass: .es)
    }

    static func buildExitEvent(with machTime: UInt64, with process: WZProcess) -> WZEvent {
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: machTime,
                       process: process,
                       payload: WZExitPayload(stat: 0),
                       eventType: .es_exit, eventClass: .es)
    }

    static func buildCreateEvent(with machTime: UInt64, with process: WZProcess) -> WZEvent {
        return WZEvent(timestamp: Date().timeIntervalSince1970,
                       machTime: machTime,
                       process: process,
                       payload: WZCreatePayload(file: WZFile.buildRandom(), type: "existing"),
                       eventType: .es_create, eventClass: .es)
    }

    /// Return the child process of this event (for fork and exec)
    var child: WZProcess {
        if self.eventType == .es_exec {
            return (self.payload as! WZExecPayload).process
        }
        if self.eventType == .es_fork {
            return (self.payload as! WZForkPayload).process
        }
        fatalError()
    }

}
