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

private enum ArgDataError: Error {
    case failed
}

private enum ArgParserError: Error {
    case unexpectedEnd
    case argumentIsNotUTF8
}


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

    public static func getArguments(for pid: pid_t) -> [String]? {
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

    public static func getPath(from pid: pid_t) -> String {
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

    public static func getPath(from token: audit_token_t) -> String {
        var mutableToken = token

        var buffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_SIZE))

        let bytesCopied = withUnsafeMutablePointer(to: &mutableToken) { tokenPtr in
            proc_pidpath_audittoken(tokenPtr, &buffer, UInt32(buffer.count))
        }

        if bytesCopied > 0 {
            return String(cString: buffer)
        } else {
            return ""
        }
    }



    public static func getPIDInfo(pid: pid_t) -> proc_bsdinfo? {
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


}











