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

import XCTest
@testable import Agent

private struct MockEvent {
    let child: WZProcess
    let parent: WZProcess

    static func buildFork(with parent: WZProcess) -> MockEvent {
        return MockEvent(child: WZProcess.build(parentAuditToken: parent.auditToken),
                         parent: parent)
    }

    static func buildRandomFork() -> MockEvent {
        let parent = WZProcess.buildRandom()
        let child = WZProcess.build(parentAuditToken: parent.auditToken)
        return MockEvent(child: child, parent: parent)
    }

    static func buildRandomExec() -> MockEvent {
        let parent = WZProcess.buildRandom()
        let child = WZProcess.build(parentAuditToken: parent.auditToken,
                                    pid: UInt32(parent.pid),
                                    pidVersion: UInt32(parent.pidVersion+1))
        return MockEvent(child: child, parent: parent)
    }

    static func buildExec(with parent: WZProcess) -> MockEvent {
        let child = WZProcess.build(parentAuditToken: parent.auditToken,
                                    pid: UInt32(parent.pid),
                                    pidVersion: UInt32(parent.pidVersion+1))
        return MockEvent(child: child, parent: parent)
    }

    static func build(parent: WZProcess) -> MockEvent {
        return MockEvent(child: WZProcess.build(parentAuditToken: parent.auditToken),
                         parent: parent)
    }
}

private class MockWZProcessProvider: WZProcessProviderProtocol {
    private var processes: [pid_t: [WZProcess]] = [:]

    func getRunningProcesses() -> [pid_t : [WZProcess]] {
        return self.processes
    }

    func setRunningProcesses(_ processes: [pid_t: [WZProcess]]) {
        self.processes = processes
    }
}


final class WZProcessTreeTests: XCTestCase {
    private var processProvider: MockWZProcessProvider!

    override func setUpWithError() throws {
        self.processProvider = MockWZProcessProvider()
    }

    func machTimeNano() -> UInt64 {
        return WZUtils.machTimeToNanoseconds(machTime: mach_absolute_time())
    }

    func testExecEventSuccess() throws {
        let exec = WZEvent.buildRandomExec()
        self.processProvider.setRunningProcesses([0: [exec.process!]])
        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(exec, .auth)

        XCTAssertEqual(exec.child.parent!.pid, exec.process!.pid)

        XCTAssertNotNil(tree.get(exec.child.key))
    }


    func testDeleteOnlyAfterProcessIsNotRetained() {
        let parent1 = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [parent1]])
        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        let exec = WZEvent.buildExecEvent(with: 1, with: parent1)

        tree.addEvent(exec, .auth)

        XCTAssertTrue(exec.process!.isRetained())
        XCTAssertFalse(exec.child.isRetained())

        XCTAssertNotNil(tree.get(exec.process!.key))

        let exit = WZEvent.buildExitEvent(with: 2, with: exec.child)
        tree.addEvent(exit, .auth)

        XCTAssertNil(tree.get(exec.process!.key))
    }

    func testInitialProcessesAreRetained() {
        let grandParent = WZProcess.buildRandom()
        let parent = WZProcess.build(parentAuditToken: grandParent.auditToken)
        let child1 = WZProcess.build(parentAuditToken: parent.auditToken)
        let child2 = WZProcess.build(parentAuditToken: parent.auditToken)

        self.processProvider.setRunningProcesses([0: [grandParent],
                                                  grandParent.pid: [parent],
                                                  parent.pid: [child1, child2]])

        XCTAssertFalse(grandParent.isRetained())
        XCTAssertFalse(parent.isRetained())
        XCTAssertFalse(child1.isRetained())
        XCTAssertFalse(child2.isRetained())

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        XCTAssertTrue(grandParent.isRetained())
        XCTAssertTrue(parent.isRetained())
        XCTAssertFalse(child1.isRetained())
        XCTAssertFalse(child2.isRetained())

        tree.addEvent(WZEvent.buildExitEvent(with: 1, with: child1), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 2, with: child2), .auth)
        XCTAssertNil(tree.get(child1.key))
        XCTAssertNil(tree.get(child2.key))
    }

    func testSeveralExecThenForkThenExec() {
        let proc1 = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [proc1]])

        // First exec event
        let exec1 = WZEvent.buildExecEvent(with: 1, with: proc1)

        // Second exec event
        let fork = WZEvent.buildForkEvent(with: 2, with: exec1.child)
        let exec2 = WZEvent.buildExecEvent(with: 3, with: fork.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(exec1, .auth)
        XCTAssertFalse(exec1.child.isRetained())
        XCTAssertTrue(exec1.process!.isRetained())

        tree.addEvent(fork, .auth)
        XCTAssertTrue(exec1.child.isRetained())

        tree.addEvent(exec2, .auth)
        XCTAssertFalse(exec2.child.isRetained())
        // assert exec2.parent (forkedProc) is retained
        XCTAssertTrue(exec2.process!.isRetained())

        tree.addEvent(WZEvent.buildExitEvent(with: 4, with: exec1.child), .auth)
        XCTAssertNotNil(tree.get(exec1.child.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: exec2.child), .auth)
        XCTAssertNil(tree.get(exec2.child.key))
        XCTAssertFalse(exec2.process!.isRetained())
        XCTAssertNil(tree.get(exec2.process!.key))
        XCTAssertNil(tree.get(exec1.child.key))
        XCTAssertNil(tree.get(exec1.process!.key))
    }

    // Dont know what else to call this :)
    func testDoubleFork_ExitFirstFork_Exec_ExitSecondFork_ExitExec() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 2, with: fork1.child)

        let exec = WZEvent.buildExecEvent(with: 3, with: fork2.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)

        XCTAssertTrue(process.isRetained())
        XCTAssertFalse(fork1.child.isRetained())

        tree.addEvent(fork2, .auth)

        XCTAssertTrue(fork1.child.isRetained())
        XCTAssertFalse(fork2.child.isRetained())

        tree.addEvent(WZEvent.buildExitEvent(with: 4, with: fork1.child), .auth)

        // Assert fork1 is not deleted as it is retained by fork2
        XCTAssertNotNil(tree.get(fork1.child.key))
        XCTAssertTrue(process.isRetained())

        tree.addEvent(exec, .auth)

        // Assert fork2 is retained by exec.child
        XCTAssertTrue(fork2.child.isRetained())
        XCTAssertFalse(exec.child.isRetained())
        XCTAssertNotNil(tree.get(fork2.child.key))
        XCTAssertNotNil(tree.get(fork1.child.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: exec.child), .auth)

        XCTAssertNil(tree.get(fork1.child.key))
        XCTAssertNil(tree.get(fork2.child.key))
        XCTAssertNil(tree.get(exec.child.key))
        XCTAssertFalse(process.isRetained())
    }

    // Dont know what else to call this :)
    func testDoubleFork_Exec_ExitFirstFork_ExitExec() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 2, with: fork1.child)

        let exec = WZEvent.buildExecEvent(with: 3, with: fork2.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)

        XCTAssertTrue(process.isRetained())
        XCTAssertFalse(fork1.child.isRetained())

        tree.addEvent(fork2, .auth)

        XCTAssertTrue(fork1.child.isRetained())
        XCTAssertFalse(fork2.child.isRetained())

        tree.addEvent(exec, .auth)

        // Assert fork2 is retained by exec.child
        XCTAssertTrue(fork2.child.isRetained())
        XCTAssertFalse(exec.child.isRetained())
        XCTAssertNotNil(tree.get(fork2.child.key))
        XCTAssertNotNil(tree.get(fork1.child.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 4, with: fork1.child), .auth)
        // Assert fork1 is not deleted as it is retained by fork2
        XCTAssertNotNil(tree.get(fork1.child.key))
        XCTAssertTrue(process.isRetained())

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: exec.child), .auth)

        XCTAssertNil(tree.get(fork1.child.key))
        XCTAssertNil(tree.get(fork2.child.key))
        XCTAssertNil(tree.get(exec.child.key))
        XCTAssertFalse(process.isRetained())
    }

    // Dont know what else to call this :)
    func testDoubleFork_Exec_ExitExec_ExitFirstFork() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 2, with: fork1.child)

        let exec = WZEvent.buildExecEvent(with: 3, with: fork2.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)

        XCTAssertTrue(process.isRetained())
        XCTAssertFalse(fork1.child.isRetained())

        tree.addEvent(fork2, .auth)

        XCTAssertTrue(fork1.child.isRetained())
        XCTAssertFalse(fork2.child.isRetained())

        tree.addEvent(exec, .auth)

        // Assert fork2 is retained by exec.child
        XCTAssertTrue(fork2.child.isRetained())
        XCTAssertFalse(exec.child.isRetained())
        XCTAssertNotNil(tree.get(fork2.child.key))
        XCTAssertNotNil(tree.get(fork1.child.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 4, with: exec.child), .auth)

        XCTAssertNotNil(tree.get(fork1.child.key))
        XCTAssertNil(tree.get(fork2.child.key))
        XCTAssertNil(tree.get(exec.child.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: fork1.child), .auth)
        // Assert fork1 is not deleted as it is retained by fork2
        XCTAssertNil(tree.get(fork1.child.key))
        XCTAssertFalse(process.isRetained())
    }

    func testProcessTreeVariation1() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 3, with: process)

        let fork3 = WZEvent.buildForkEvent(with: 2, with: fork1.child)
        let fork4 = WZEvent.buildForkEvent(with: 4, with: fork2.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)
        tree.addEvent(fork3, .auth)

        tree.addEvent(fork2, .auth)
        tree.addEvent(fork4, .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: fork1.child), .auth)

        let exec1 = WZEvent.buildExecEvent(with: 6, with: fork3.child)
        let exec2 = WZEvent.buildExecEvent(with: 7, with: fork4.child)

        tree.addEvent(exec1, .auth)
        tree.addEvent(exec2, .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 8, with: exec1.child), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 9, with: exec2.child), .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 10, with: fork2.child), .auth)

        XCTAssertTrue(tree.size() == 1)
    }

    func testProcessTreeVariation2() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 3, with: process)

        let fork3 = WZEvent.buildForkEvent(with: 2, with: fork1.child)
        let fork4 = WZEvent.buildForkEvent(with: 4, with: fork2.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)
        tree.addEvent(fork3, .auth)

        tree.addEvent(fork2, .auth)
        tree.addEvent(fork4, .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 5, with: fork1.child), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 6, with: fork2.child), .auth)

        let exec1 = WZEvent.buildExecEvent(with: 7, with: fork3.child)
        let exec2 = WZEvent.buildExecEvent(with: 8, with: fork4.child)

        tree.addEvent(exec1, .auth)
        tree.addEvent(exec2, .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 9, with: exec1.child), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 10, with: exec2.child), .auth)

        XCTAssertTrue(tree.size() == 1)
    }

    func testProcessTreeVariation3() {
        let process = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [process]])

        let fork1 = WZEvent.buildForkEvent(with: 1, with: process)
        let fork2 = WZEvent.buildForkEvent(with: 3, with: process)

        let fork3 = WZEvent.buildForkEvent(with: 2, with: fork1.child)
        let fork4 = WZEvent.buildForkEvent(with: 4, with: fork2.child)

        let exec1 = WZEvent.buildExecEvent(with: 5, with: fork3.child)
        let exec2 = WZEvent.buildExecEvent(with: 6, with: fork4.child)

        let tree = WZProcessTree(clientIDs: [.auth], processProvider: self.processProvider)

        tree.addEvent(fork1, .auth)
        tree.addEvent(fork3, .auth)

        tree.addEvent(fork2, .auth)
        tree.addEvent(fork4, .auth)

        tree.addEvent(exec1, .auth)
        tree.addEvent(exec2, .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 7, with: exec1.child), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 8, with: exec2.child), .auth)

        tree.addEvent(WZEvent.buildExitEvent(with: 9, with: fork1.child), .auth)
        tree.addEvent(WZEvent.buildExitEvent(with: 10, with: fork2.child), .auth)

        XCTAssertTrue(tree.size() == 1)
    }


    func testProcessTreeGetAfterExit() {
        let parent1 = WZProcess.buildRandom()

        self.processProvider.setRunningProcesses([0: [parent1]])
        let tree = WZProcessTree(clientIDs: [.auth, .notify], processProvider: self.processProvider)

        let exec = WZEvent.buildExecEvent(with: 1, with: parent1)

        tree.addEvent(exec, .auth)

        XCTAssertTrue(exec.process!.isRetained())
        XCTAssertFalse(exec.child.isRetained())

        XCTAssertNotNil(tree.get(exec.process!.key))

        tree.addEvent(WZEvent.buildExitEvent(with: 3, with: exec.child), .auth)

        XCTAssertNotNil(tree.get(exec.child.key))

        tree.addEvent(WZEvent.buildCreateEvent(with: 2, with: exec.child), .notify)

        XCTAssertNotNil(tree.get(exec.child.key))

        tree.addEvent(WZEvent.buildCreateEvent(with: 4, with: parent1), .notify)

        XCTAssertNil(tree.get(exec.child.key))
    }


}
