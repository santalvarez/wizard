//
//  String+Extensions.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import CryptoKit
import Darwin

fileprivate let system_glob = Darwin.glob


public extension String {
    func removeLeadingSpaces() -> String {
        guard let index = firstIndex(where: { !CharacterSet(charactersIn: String($0)).isSubset(of: .whitespaces) }) else {
            return self
        }
        return String(self[index...])
    }

    var md5: String {
        let computed = Insecure.MD5.hash(data: self.data(using: .utf8)!)
        return computed.map { String(format: "%02hhx", $0) }.joined()
    }

    func base64Encoded() -> String? {
        return data(using: .utf8)?.base64EncodedString()
    }

    func base64Decoded() -> String? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func padLeft(_ length: Int, withPad: String = " ") -> String {
        return self.padding(toLength: length, withPad: withPad, startingAt: 0)
    }

    func glob() -> [String] {
        var globResult = glob_t()
        defer { globfree(&globResult) }

        let result = system_glob(self.cString(using: .utf8), GLOB_TILDE | GLOB_BRACE | GLOB_MARK, nil, &globResult)
        guard result == 0 else {
            return []
        }

        var matches: [String] = []
        for i in 0..<Int(globResult.gl_matchc) {
            if let match = String(validatingUTF8: globResult.gl_pathv[i]!) {
                matches.append(match)
            }
        }

        return matches
    }

}

