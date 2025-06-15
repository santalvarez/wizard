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
import OSLog


public final class WZFileCache {
    public typealias FilePath = String

    private let fileCache = LRUCache<FilePath, WZFile>(countLimit: 20000)

    public static let shared = WZFileCache()

    public func emptyCache() {
        self.fileCache.emptyCache()
    }

    public func getFileSafely(by file: es_file_t) -> WZFile? {
        guard let cachedFile = self.fileCache.get(forKey: file.path.description) else {
            Logger.Agent.debug("File not cached. \(file.path.description, privacy: .public)")
            return nil
        }

        // Check the file hasn't been modified
        guard cachedFile.metadata?.st_dev == file.stat.st_dev,
              cachedFile.metadata?.st_ino == file.stat.st_ino,
              cachedFile.metadata?.st_mtimespec.seconds == file.stat.st_mtimespec.seconds else {
            Logger.Agent.debug("File has been modified. \(file.path.description, privacy: .public)")
            return nil
        }
        return cachedFile
    }

    public func getFileUnSafely(by path: FilePath) -> WZFile? {
        return self.fileCache.get(forKey: path)
    }

    public func saveFile(_ file: WZFile, with path: FilePath) {
        self.fileCache.save(file, forKey: path)
    }

    public func removeFile(_ path: FilePath) {
        self.fileCache.removeValue(forKey: path)
    }
}
