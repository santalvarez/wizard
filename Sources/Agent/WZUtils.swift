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
import OSLog
import CryptoKit


public struct WZUtils {

    private static var timebase: mach_timebase_info_data_t = {
        var timebase: mach_timebase_info_data_t = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        return timebase
    }()

    public static func machTimeToNanoseconds(machTime: UInt64) -> UInt64 {
        return machTime * UInt64(timebase.numer) / UInt64(timebase.denom)
    }

    public static func currentMachTimeNano() -> UInt64 {
        Self.machTimeToNanoseconds(machTime: mach_absolute_time())
    }

    public static func getRunningPIDs() -> [pid_t]? {
        let kinfo_stride = MemoryLayout<kinfo_proc>.stride
        var bufferSize: Int = 0
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]

        guard sysctl(&name, u_int(name.count), nil, &bufferSize, nil, 0) == 0 else {
            return nil
        }
        let count = bufferSize / kinfo_stride
        var buffer = Array(repeating: kinfo_proc(), count: count)
        guard sysctl(&name, u_int(name.count), &buffer, &bufferSize, nil, 0) == 0 else {
            return nil
        }
        let newCount = bufferSize / kinfo_stride
        if count > newCount {
            _ = buffer.dropLast(count - newCount)
        }
        let sorted = buffer.sorted { first, second in
            first.kp_proc.p_pid < second.kp_proc.p_pid
        }

        return sorted.compactMap {
            if $0.kp_proc.p_pid < 1 { return nil }
            return $0.kp_proc.p_pid
        }
    }

    public static func calculateSHA256(_ path: String) -> String? {
        Logger.Agent.debug("Calculating SHA256 for \(path, privacy: .public)")
        if FileManager.default.fileExists(atPath: path) {
            let bufferSize = 1024 * 1024 * 2 // 2MB
            var buffer = [UInt8](repeating: 0, count: bufferSize)

            var hasher = SHA256()

            guard let inputStream = InputStream(fileAtPath: path) else {
                return nil
            }

            inputStream.open()
            defer {
                inputStream.close()
            }

            while inputStream.hasBytesAvailable {
                let bytesRead = inputStream.read(&buffer, maxLength: bufferSize)
                if bytesRead < 0 {
                    //Stream error occured
                    return nil
                } else if bytesRead == 0 {
                    //EOF
                    break
                }

                hasher.update(data: Data(bytes: &buffer, count: bytesRead))
            }
            return hasher.finalize().compactMap { String(format: "%02x", $0) }.joined()
        }
        return nil
    }

}











