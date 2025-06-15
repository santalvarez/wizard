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

private enum ArgDataError: Error {
    case failed
}

private enum ArgParserError: Error {
    case unexpectedEnd
    case argumentIsNotUTF8
}


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

    static func getPathFromPID(pid: pid_t) -> String {
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer {
            pathBuffer.deallocate()
        }

        guard proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN)) > 0 else {
            return ""
        }
        let path = String(cString: pathBuffer)
        return path
    }

    // https://github.com/themittenmac/TrueTree/blob/99972da3963bd57b6a64563c36b87030e024d1b9/Src/process.swift#L70
    typealias rpidFunc = @convention(c) (CInt) -> CInt
    static func getResponsiblePID(pid: pid_t) -> CInt? {
        // Get responsible pid using private Apple API
        let rpidSym:UnsafeMutableRawPointer! = dlsym(UnsafeMutableRawPointer(bitPattern: -1), "responsibility_get_pid_responsible_for_pid")

        let pidCheck = unsafeBitCast(rpidSym, to: rpidFunc.self)(CInt(pid))

        if (pidCheck == -1) {
            return nil
        }

        return pidCheck
    }

    static func getPIDInfo(pid: pid_t) -> proc_bsdinfo? {
        let pidInfoSize = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let pidInfo = UnsafeMutablePointer<proc_bsdinfo>.allocate(capacity: 1)
        defer {
            pidInfo.deallocate()
        }

        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pidInfo, pidInfoSize) == pidInfoSize  else {
            return nil
        }

        return pidInfo.pointee
    }


    static func getPIDEproc(pid: pid_t) -> eproc? {
        var kinfo = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride


        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]

        guard sysctl(&mib, 4, &kinfo, &size, nil, 0) == noErr else {
            return nil
        }

        return kinfo.kp_eproc
    }

    /**
     Return arguments for given pid
    */
    static func getArguments(for pid: pid_t) -> [String]? {
        // If the process isExec then we should get the arguments using the ppid else we should get the arguments using the pid

        guard let argumentsData = try? argumentData(for: pid),
              let arguments =  try? argumentsFromArgumentData(argumentsData) else {
            return nil
        }
        return arguments
    }

    private static func argumentData(for pid: pid_t) throws -> Data {
        // There should be a better way to get a process’s arguments
        // (FB9149624) but right now you have to use `KERN_PROCARGS2`
        // and then parse the results.
        var argMax: CInt = 0
        var argMaxSize = size_t(MemoryLayout.size(ofValue: argMax))
        guard sysctlbyname("kern.argmax", &argMax, &argMaxSize, nil, 0) >= 0 else {
            throw ArgDataError.failed
        }
        precondition(argMaxSize != 0)
        var result = Data(count: Int(argMax))
        let resultSize = try result.withUnsafeMutableBytes { buf -> Int in
            var mib: [CInt] = [
                CTL_KERN,
                KERN_PROCARGS2,
                pid
            ]
            var bufSize = buf.count
            guard sysctl(&mib, CUnsignedInt(mib.count), buf.baseAddress!, &bufSize, nil, 0) >= 0 else {
                throw ArgDataError.failed
            }
            return bufSize
        }
        result = result.prefix(resultSize)
        return result
    }

    private static func argumentsFromArgumentData(_ data: Data) throws -> [String] {

        // <https://opensource.apple.com/source/adv_cmds/adv_cmds-176/ps/print.c.auto.html>

        // Parse `argc`.  We’re assuming the value is little endian here, which is
        // currently accurate but it could be a problem if we’ve “gone back to
        // metric”.

        var remaining = data[...]
        guard remaining.count >= 6 else {
            throw ArgParserError.unexpectedEnd
        }
        let count32 = remaining.prefix(4).reversed().reduce(0, { $0 << 8 | UInt32($1) })
        remaining = remaining.dropFirst(4)

        // Skip the saved executable path.

        remaining = remaining.drop(while: { $0 != 0 })
        remaining = remaining.drop(while: { $0 == 0 })

        // Now parse `argv[0]` through `argv[argc - 1]`.

        var result: [String] = []
        for _ in 0..<count32 {
            let argBytes = remaining.prefix(while: { $0 != 0 })
            guard let arg = String(bytes: argBytes, encoding: .utf8) else {
                throw ArgParserError.argumentIsNotUTF8
            }
            result.append(arg)
            remaining = remaining.dropFirst(argBytes.count)
            guard remaining.count != 0 else {
                throw ArgParserError.unexpectedEnd
            }
            remaining = remaining.dropFirst()
        }
        return result
    }

}


extension WZProcess {
    public convenience init?(auditToken: audit_token_t) {
        let pid = audit_token_to_pid(auditToken)
        guard let pidInfo = Self.getPIDInfo(pid: pid),
              let parentAuditToken = try? audit_token_t(pid: pid_t(pidInfo.pbi_ppid)) else {
            return nil
        }
        // TODO: agregar el rpid aca
        self.init(file: WZFile(auditToken: auditToken),
                  auditToken: auditToken, parentAuditToken: parentAuditToken,
                  startTime: Int(pidInfo.pbi_start_tvsec),
                  arguments: Self.getArguments(for: pid)?.joined(separator: " "))
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
                  arguments: Self.getArguments(for: argsPID)?.joined(separator: " "),
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

