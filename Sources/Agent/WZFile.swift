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
import EndpointSecurity
import SwiftRuleEngine

@StringSubscriptable
public final class WZFile: Encodable {
    public let path: String
    public let pathTruncated: Bool
    public let name: String
    public let isEsClient: Bool
    @Atomic public var metadata: stat?
    public let lightweight: Bool
    @LazyAtomic public var sha256: String?
    @LazyAtomic public var signature: WZSignature

    public init(path: String, pathTruncated: Bool,
         name: String, isEsClient: Bool = false,
         metadata: stat? = nil, lightweight: Bool = false) {
        self.path = path
        self.pathTruncated = pathTruncated
        self.name = name
        self.isEsClient = isEsClient
        self.lightweight = lightweight
        self.metadata = metadata
        _sha256 = LazyAtomic(wrappedValue: {
            if lightweight { return nil }
            return WZUtils.calculateSHA256(path)
        }())
        _signature = LazyAtomic(wrappedValue: {
            if lightweight { return WZSignature()}
            return WZSignature(path: path)
        }())
    }

    static func getStat(path: String) -> stat? {
        var stat = stat()
        if lstat(path, &stat) == 0 {
            return stat
        }
        return nil
    }

    /**
     Returns a dictionary with the cputype as key and the offset as value.
     If the file is not a FAT file, the dictionary will be empty.
    */
    static func getFATMachOSlices(_ path: String) -> [Int32: UInt64] {
        var slices: [Int32: UInt64] = [:]

        guard let file = FileHandle(forReadingAtPath: path) else {
            return slices
        }

        defer { file.closeFile() }

        let headerData = file.readData(ofLength: MemoryLayout<fat_header>.size)
        if headerData.count < MemoryLayout<fat_header>.size {
            return slices
        }
        var fatHeader = headerData.withUnsafeBytes { $0.load(as: fat_header.self) }

        guard fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_CIGAM ||
              fatHeader.magic == FAT_MAGIC_64 || fatHeader.magic == FAT_CIGAM_64 else {
            return slices
        }

        let is64Bit = fatHeader.magic == FAT_MAGIC_64 || fatHeader.magic == FAT_CIGAM_64
        let byteSwapped = fatHeader.magic == FAT_CIGAM || fatHeader.magic == FAT_CIGAM_64

        if byteSwapped {
            swap_fat_header(&fatHeader, NXByteOrder(0))
        }

        for _ in 0..<fatHeader.nfat_arch {
            // Iterate number of architectures
            if is64Bit {
                // 64 bit
                let archData = file.readData(ofLength: MemoryLayout<fat_arch_64>.size)
                var arch = archData.withUnsafeBytes { $0.load(as: fat_arch_64.self) }
                swap_fat_arch_64(&arch, 1, NXByteOrder(0))
                slices[arch.cputype] = arch.offset
            } else {
                // 32 bit
                let archData = file.readData(ofLength: MemoryLayout<fat_arch>.size)
                var arch = archData.withUnsafeBytes { $0.load(as: fat_arch.self) }
                swap_fat_arch(&arch, 1, NXByteOrder(0))
                slices[arch.cputype] = UInt64(arch.offset)
            }
        }

        return slices
    }

}


extension WZFile {
    /**
     File init for directories
     - Parameter dir: The es_file_t object
     - Parameter fileName: This is used for ES_DESTINATION_TYPE_NEW_PATH objects that indicate
        the name of the file trying to be created. If not provided, the name will be extracted
        from the path
     */
    public convenience init(dir: es_file_t, fileName: String?) {
        // TODO: add the filename to the path
        // also add an isDir property
        // that will be set if the stat call to the created path fails
        self.init(path: dir.path.description, pathTruncated: dir.path_truncated,
                  name: (fileName != nil) ? fileName! : (dir.path.description as NSString).lastPathComponent,
                  metadata: dir.stat, lightweight: true)
    }

    public convenience init(path: String) {
        self.init(path: path, pathTruncated: false,
                  name: (path as NSString).lastPathComponent,
                  metadata: Self.getStat(path: path))
    }


    /**
     File init for es_file_t objects
     - Parameter file: The es_file_t object
     - Parameter lightweight: If true, the file will not calculate the sha256 and signature
     */
    public convenience init(file: es_file_t, isEsClient: Bool = false, lightweight: Bool=false) {
        let path = file.path.description
        self.init(path: path, pathTruncated: file.path_truncated,
                  name: (path as NSString).lastPathComponent,
                  isEsClient: isEsClient, metadata: file.stat,
                  lightweight: lightweight)
    }

    public convenience init(auditToken: audit_token_t) {
        let path = WZUtils.getPath(from: auditToken)
        self.init(path: path, pathTruncated: false,
                  name: (path as NSString).lastPathComponent,
                  metadata: Self.getStat(path: path))
    }
}
