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
import Darwin
import OSLog
import EndpointSecurity


public final class WZProcessTree {
    private var tree: [WZProcessKey: WZProcess] = [:]
    private let lock = NSLock()
    private let processProvider: WZProcessProviderProtocol
    private let logger = Logger(subsystem: Logger.subsystem, category: "ProcessTree")

    // Track each client’s latest observed machTime
    private var latestMachTimes: [WZESClientID: UInt64] = [:]

    // Keep a list of processes we want to delete but are waiting for all clients to pass their exitTime
    private var pendingDeletions: [WZProcessKey: UInt64] = [:]


    public static let shared = WZProcessTree(clientIDs: WZESClientID.allCases,
                                      processProvider: WZProcessProvider())

    public init(clientIDs: [WZESClientID], processProvider: WZProcessProviderProtocol) {
        self.processProvider = processProvider
        self.fillTree()
        // Initialize all clients' latest machTimes to zero
        clientIDs.forEach{ self.latestMachTimes[$0] = 0 }
    }


    /// Return a process based on its audit token
    public func get(_ pkey: WZProcessKey) -> WZProcess? {
        lock.lock()
        defer { lock.unlock() }
        return self.tree[pkey]
    }

    public func addEvent(_ event: WZEvent, _ clientID: WZESClientID) {
        lock.lock()
        defer { lock.unlock() }

        // 1) Update this client’s latest machTime
        self.latestMachTimes[clientID] = max(self.latestMachTimes[clientID] ?? 0, event.machTime)

        // 2) Process the actual event
        if event.eventType == .es_exec {
            guard let payload = event.payload as? WZExecPayload else {
                // This is a programming error
                fatalError()
            }
            self.addExec(payload.process, event.process!, event.machTime, clientID)
        } else if event.eventType == .es_fork {
            guard let payload = event.payload as? WZForkPayload else {
                // This is a programming error
                fatalError()
            }
            self.addFork(payload.process,  event.machTime, clientID)
        } else if event.eventType == .es_exit {
            self.addExit(event.process!.key, event.machTime, clientID)
        }

        // 3) After handling the new event, try to remove any pending deletions
        self.processPendingDeletionsNoLock()
    }

    /// Add a process to the tree
    private func addExec(_ process: WZProcess, _ parent: WZProcess,
                         _ machTimeNano: UInt64, _ clientID: WZESClientID) {
        assert(process.pid == parent.pid)

        guard let parentInTree = self.tree[parent.key] else {
            // In theory this should not happen
            return
        }

        process.parent = parentInTree
        self.tree[process.key] = process
        process.retainParents()

        self.deleteNoLock(parent.key)
    }

    private func addFork(_ process: WZProcess, _ machTimeNano: UInt64,
                         _ clientID: WZESClientID) {
        guard let parent = self.tree[process.parentKey] else {
            // In theory this should not happen
            return
        }

        process.parent = parent
        self.tree[process.key] = process
        process.retainParents()
    }

    /// Delete a process from the tree, this is called on process exit events
    private func addExit(_ pkey: WZProcessKey, _ machTimeNano: UInt64,
                         _ clientID: WZESClientID) {
        // 1) Check if this exit event is definitely past all clients
        let minMachTime = self.latestMachTimes.values.min() ?? 0
        if machTimeNano <= minMachTime {
            // Safe to remove right now
            self.deleteNoLock(pkey)
        } else {
            // Keep track of this process for later removal
            self.pendingDeletions[pkey] = machTimeNano
        }
    }

    /// After updating any client’s machTime, try removing any processes whose exitTime
    /// is now ≤ the new global minimum of all clients’ machTimes.
    private func processPendingDeletionsNoLock() {
        let minMachTime = self.latestMachTimes.values.min() ?? 0

        // Collect all keys whose stored exit time is now safe for removal
        let readyToDelete = pendingDeletions.filter { (_, exitTime) in
            exitTime <= minMachTime
        }.map { $0.key }

        for pkey in readyToDelete {
            self.deleteNoLock(pkey)
            self.pendingDeletions.removeValue(forKey: pkey)
        }
    }

    private func deleteNoLock(_ pkey: WZProcessKey) {
        guard let process = self.tree[pkey] else {
            return
        }

        if process.isRetained() {
            process.deleted = true
        } else {
            self.releaseParents(process)
            self.tree.removeValue(forKey: pkey)
        }
    }

    private func releaseParents(_ process: WZProcess) {
        var currentParent: WZProcess? = process.parent
        while let parent = currentParent {
            parent.release()

            if parent.deleted && !parent.isRetained() {
                self.releaseParents(parent)
                self.tree.removeValue(forKey: parent.key)
            }
            currentParent = parent.parent
        }
    }

    /// Fill the tree with currently active processes
    private func fillTree() {
        lock.withLock {
            self.logger.log("Obtaining running processes")
            let parentProcsDict = self.processProvider.getRunningProcesses()

            let rootProcessID: pid_t = 0

            self.logger.log("Starting to fill process tree")
            self.fill(rootProcessID, parent: nil, with: parentProcsDict)
            self.logger.log("Finished filling process tree")
        }
    }

    // A helper function to recursively add processes to the tree
    private func fill(_ pid: pid_t, parent: WZProcess?,
                      with parentProcsDict: [pid_t: [WZProcess]]) {
        guard let processes = parentProcsDict[pid],
              !processes.isEmpty else {
            return
        }

        for process in processes {
            process.parent = parent
            self.tree[process.key] = process
            process.retainParents()

            // Recursively add children
            self.fill(process.pid, parent: process, with: parentProcsDict)
        }
    }

    public func size() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return self.tree.count
    }
}
