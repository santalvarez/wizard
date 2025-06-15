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


public protocol WZProcessProviderProtocol {
    func getRunningProcesses() -> [pid_t: [WZProcess]]
}

public struct WZProcessProvider: WZProcessProviderProtocol {
    public func getRunningProcesses() -> [pid_t: [WZProcess]] {
        guard let pids = WZUtils.getRunningPIDs() else {
            return [:]
        }

        var parentProcsDict = [pid_t: [WZProcess]]()
        for pid in pids {
            guard let process = WZProcess(pid: pid) else {
                continue
            }

            if parentProcsDict[process.ppid] != nil {
                parentProcsDict[process.ppid]!.append(process)
            } else {
                parentProcsDict[process.ppid] = [process]
            }
        }
        return parentProcsDict
    }
}
