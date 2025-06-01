//
//  audit_token_t+Extensions.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation


extension audit_token_t {
    public init(pid: Int32) throws {
        var taskName: mach_port_name_t = mach_port_name_t()
        let result = task_name_for_pid(mach_task_self_, pid, &taskName)
        if result != KERN_SUCCESS {
            throw NSError(domain: NSMachErrorDomain, code: Int(result))
        }
        try self.init(task: taskName)
    }

    public init(task: task_name_t) throws {
        self.init()

        let TASK_AUDIT_TOKEN_COUNT = MemoryLayout<audit_token_t>.stride / MemoryLayout<natural_t>.stride
        var size = mach_msg_type_number_t(TASK_AUDIT_TOKEN_COUNT)

        let result = withUnsafeMutablePointer(to: &self) {
            $0.withMemoryRebound(to: Int32.self, capacity: TASK_AUDIT_TOKEN_COUNT) {
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &size)
            }
        }

        if result != KERN_SUCCESS {
            throw NSError(domain: NSMachErrorDomain, code: Int(result))
        }

    }

    public init?(data: Data) {
        guard data.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        self = data.withUnsafeBytes { buf in
            buf.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee
        }
    }

    var data: Data {
        return withUnsafeBytes(of: self.val) { Data($0) }
    }
}

extension audit_token_t: Hashable {
    public static func == (lhs: audit_token_t, rhs: audit_token_t) -> Bool {
        return lhs.val.0 == rhs.val.0 &&
               lhs.val.1 == rhs.val.1 &&
               lhs.val.2 == rhs.val.2 &&
               lhs.val.3 == rhs.val.3 &&
               lhs.val.4 == rhs.val.4 &&
               lhs.val.5 == rhs.val.5 &&
               lhs.val.6 == rhs.val.6 &&
               lhs.val.7 == rhs.val.7
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(val.0)
        hasher.combine(val.1)
        hasher.combine(val.2)
        hasher.combine(val.3)
        hasher.combine(val.4)
        hasher.combine(val.5)
        hasher.combine(val.6)
        hasher.combine(val.7)
    }
}

extension audit_token_t: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.data)
    }
}

