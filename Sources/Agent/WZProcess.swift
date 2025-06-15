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
//

import Foundation
import System
import EndpointSecurity
import SwiftRuleEngine
import OSLog


/// Contains information about a process
@StringSubscriptable
public final class WZProcess {
    public let file: WZFile
    public let auditToken: audit_token_t
    public let parentAuditToken: audit_token_t
    public let responsibleAuditToken: audit_token_t?

    /// PID of the process
    public let pid: Int32
    public let pidVersion: pid_t

    /// Responsible PID of the process
    public var rpid: Int32?
    /// Parent PID of the process
    public let ppid: pid_t
    public let originalPPID: pid_t?

    /// User ID of the process (effective)
    public let uid: UInt32
    /// Real user ID of the process
    public let ruid: UInt32

    /// Group ID of the process (effective)
    public let gid: gid_t
    /// Real group ID of the process
    public let rgid: gid_t

    public let startTime: Int?
    public let sessionID: pid_t?
    public let tty: String?
    public var env: [String: String]?
    public let arguments: String?
    @Atomic public var parent: WZProcess?
    // Indicates how many processes are referencing it.
    // E.g: grandParent -> parent -> child (refCound of grandParent is 2)
    public var refCount = 0
    // Indicated wether the process has been marked for deletion by the WZProcessTree
    public var deleted: Bool = false

    public var parentTeamIDs: [String] {
        var parent: WZProcess? = self.parent
        var teamIDs = [String]()
        while let current = parent {
            if let teamID = current.file.signature.teamID {
                teamIDs.append(teamID)
            }
            parent = current.parent
        }
        return teamIDs
    }

    public var parentNames: [String] {
        var parent: WZProcess? = self.parent
        var names = [String]()
        while let current = parent {
            names.append(current.file.name)
            parent = current.parent
        }
        return names
    }

    public var parentBundleIDs: [String] {
        var parent: WZProcess? = self.parent
        var bundleIDs = [String]()
        while let current = parent {
            if let bundleID = current.file.signature.bundleID {
                bundleIDs.append(bundleID)
            }
            parent = current.parent
        }
        return bundleIDs
    }

    /// Indicates if the process generated an exec event (this is usefull for obtaining the arguments)
    private var isExecParent: Bool

    public init(file: WZFile, auditToken: audit_token_t, parentAuditToken: audit_token_t,
         responsibleAuditToken: audit_token_t? = nil,
         originalPPID: pid_t? = nil, startTime: Int? = nil,
         sessionID: pid_t? = nil, tty: String? = nil, env: [String : String]? = nil,
         arguments: String? = nil, isExecParent: Bool = false) {
        self.file = file
        self.auditToken = auditToken
        self.parentAuditToken = parentAuditToken
        self.responsibleAuditToken = responsibleAuditToken
        self.pid = audit_token_to_pid(auditToken)
        self.pidVersion = audit_token_to_pidversion(auditToken)
        self.rpid = (responsibleAuditToken != nil) ? audit_token_to_pid(responsibleAuditToken!): nil
        self.ppid = audit_token_to_pid(parentAuditToken)
        self.originalPPID = originalPPID
        self.uid = audit_token_to_euid(auditToken)
        self.ruid = audit_token_to_ruid(auditToken)
        self.gid = audit_token_to_egid(auditToken)
        self.rgid = audit_token_to_rgid(auditToken)
        self.startTime = startTime
        self.sessionID = sessionID
        self.tty = tty
        self.env = env
        self.arguments = arguments
        self.isExecParent = isExecParent
    }

    public func isWizardSigned() -> Bool {
        return self.file.signature.teamID == ""
    }

    private static func buildExecutableSafely(from process: es_process_t,
                                              _ fileCache: WZFileCache) -> WZFile {
        guard let cachedExecutable = fileCache.getFileSafely(by: process.executable.pointee) else {
            let newExecutable = WZFile(file: process.executable.pointee, isEsClient: process.is_es_client)
            fileCache.saveFile(newExecutable, with: newExecutable.path)
            return newExecutable
        }

        // We update file metadata as it can change without affecting the file
        cachedExecutable.metadata = process.executable.pointee.stat
        return cachedExecutable
    }
}


extension WZProcess {
    public convenience init?(auditToken: audit_token_t) {
        let pid = audit_token_to_pid(auditToken)
        guard let pidInfo = WZUtils.getPIDInfo(pid: pid),
              let parentAuditToken = try? audit_token_t(pid: pid_t(pidInfo.pbi_ppid)) else {
            return nil
        }
        self.init(file: WZFile(auditToken: auditToken),
                  auditToken: auditToken, parentAuditToken: parentAuditToken,
                  startTime: Int(pidInfo.pbi_start_tvsec),
                  arguments: WZUtils.getArguments(for: pid)?.joined(separator: " "))
    }

    public convenience init(proc: es_process_t, isExecParent: Bool = false,
                     fileCache: WZFileCache=WZFileCache.shared) {

        // In exec events both the child and parent have the same PID so if we are the parent of an exec we
        // need to grab the arguments of the parents parent.
        let argsPID = isExecParent ? audit_token_to_pid(proc.parent_audit_token) : audit_token_to_pid(proc.audit_token)

        self.init(file: Self.buildExecutableSafely(from: proc, fileCache),
                  auditToken: proc.audit_token, parentAuditToken: proc.parent_audit_token,
                  responsibleAuditToken: proc.responsible_audit_token,
                  originalPPID: proc.original_ppid,
                  startTime: proc.start_time.tv_sec,
                  sessionID: proc.session_id, tty: proc.tty?.pointee.path.description,
                  arguments: WZUtils.getArguments(for: argsPID)?.joined(separator: " "),
                  isExecParent: isExecParent)
    }

    public convenience init?(pid: pid_t) {
        guard let at = try? audit_token_t(pid: pid) else {
            return nil
        }
        self.init(auditToken: at)
    }
}

extension WZProcess: Encodable {
    private func encodeCommonProperties(into container: inout KeyedEncodingContainer<CodingKeys>) throws {
        try container.encode(file, forKey: .file)
        try container.encode(auditToken, forKey: .auditToken)
        try container.encode(parentAuditToken, forKey: .parentAuditToken)
        try container.encode(responsibleAuditToken, forKey: .responsibleAuditToken)
        try container.encode(pid, forKey: .pid)
        try container.encode(pidVersion, forKey: .pidVersion)
        try container.encode(rpid, forKey: .rpid)
        try container.encode(ppid, forKey: .ppid)
        try container.encode(originalPPID, forKey: .originalPPID)
        try container.encode(uid, forKey: .uid)
        try container.encode(ruid, forKey: .ruid)
        try container.encode(gid, forKey: .gid)
        try container.encode(rgid, forKey: .rgid)
        try container.encode(startTime, forKey: .startTime)
        try container.encode(sessionID, forKey: .sessionID)
        try container.encode(tty, forKey: .tty)
        try container.encode(env, forKey: .env)
        try container.encode(arguments, forKey: .arguments)
    }

    // Conformance to Encodable
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try encodeCommonProperties(into: &container)
    }

    // Custom method that also handles the parent property
    public func encodeWithParent(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try encodeCommonProperties(into: &container)
        try self.parent?.encodeWithParent(to: container.superEncoder(forKey: .parent))
    }

    enum CodingKeys: String, CodingKey {
        case file, auditToken, parentAuditToken, responsibleAuditToken,
             pid, pidVersion, rpid, ppid, originalPPID, uid, ruid, gid,
             rgid, startTime, sessionID, tty, env, arguments, parent
    }
}


extension WZProcess {
    public func isRetained() -> Bool { return refCount > 0 }
    public func retain() { refCount += 1 }
    public func release() { refCount -= 1 }

    public var key: WZProcessKey {
        return WZProcessKey(pid: self.pid, pidVersion: self.pidVersion)
    }
    public var parentKey: WZProcessKey {
        return WZProcessKey(pid: audit_token_to_pid(self.parentAuditToken),
                            pidVersion: audit_token_to_pidversion(self.parentAuditToken))
    }

    public func retainParents() {
        var current: WZProcess? = self.parent
        while let process = current {
            process.retain()
            current = process.parent
        }
    }
}

