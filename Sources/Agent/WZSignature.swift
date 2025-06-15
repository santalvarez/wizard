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
import Security
import EndpointSecurity
import CryptoKit
import SwiftRuleEngine


let kSecCSDefaultFlags: UInt32 = 0x0
let kSecCSStaticFlags: UInt32 = kSecCSCheckNestedCode | kSecCSCheckAllArchitectures
                                | kSecCSDoNotValidateResources | SecCSFlags.noNetworkAccess.rawValue
let kAppleRequirement = WZSignature.getRequirementFromString("anchor apple")!


@StringSubscriptable(withKeys: false)
public struct WZSignature: Encodable {
    public var status: WZSignatureStatus = .unknown
    public var statusCode: OSStatus = 0
    public var statusDescription: String = ""
    public var isPlatformBinary: Bool?
    public var signingDate: Date?
    public var format: String?
    public var bundleID: String?
    public var teamID: String?
    public var cdHash: String?
    public var flags: UInt32?
    public var mainExecutable: String?
    public var entitlements: [String: Any]?
    public var certificates: [WZCertificate]?

    static private let keys: [String: PartialKeyPath<WZSignature>] = [
        "status": \.status.rawValue,
        "status_code": \.statusCode,
        "status_description": \.statusDescription,
        "is_platform_binary": \.isPlatformBinary,
        "signing_date": \.signingDate?.timeIntervalSince1970,
        "format": \.format,
        "bundle_id": \.bundleID,
        "team_id": \.teamID,
        "cd_hash": \.cdHash,
        "flags": \.flags,
        "main_executable": \.mainExecutable,
        "entitlements": \.entitlements,
        "certificates": \.certificates
    ]

    // TODO: make entitlements encodable
    // We define only the attributes we want to encode
    private enum CodingKeys: String, CodingKey {
        case status, statusDescription, statusCode, signingDate, format,
             flags, certificates, bundleID, teamID, cdHash,
             mainExecutable, isPlatformBinary
    }

    public init() {}

    /**
     Given an audit token of a process, obtain the signature details dynamically or statically.

     - parameter auditToken: The audit token of the process to inspect
     - parameter validate: Whether to validate the signature or not. If the
                           validation fails, the other attributes will be empty.
     - parameter req: Optional requirement to use for validation.
    */
    public init(auditToken: audit_token_t, validate: Bool=true, req: SecRequirement?=nil) {
        do {
            let secCode = try Self.getSecCode(for: auditToken.data)

            if validate {
                try Self.validateSecCode(secCode, with: req)
                self.status = .valid
                self.isPlatformBinary = Self.isAppleSigned(secCode: secCode)
            }

            let staticCode = try Self.getStaticCode(for: secCode,
                                                    flags: kSecCSDefaultFlags)

            let info = try Self.getSignatureInfo(staticCode, flags: kSecCSDynamicInformation)

            self.format = Self.getSignatureInfoValue(for: kSecCodeInfoFormat, from: info)
            self.teamID = Self.getSignatureInfoValue(for: kSecCodeInfoTeamIdentifier, from: info)
            let mainExec: URL? = Self.getSignatureInfoValue(for: kSecCodeInfoMainExecutable, from: info)
            self.mainExecutable = mainExec?.path
            self.bundleID = Self.getSignatureInfoValue(for: kSecCodeInfoIdentifier, from: info)
            self.cdHash = Self.getCDHash(from: info)?.uppercased()
            self.flags = Self.getSignatureInfoValue(for: kSecCodeInfoFlags, from: info)
            self.signingDate = Self.getSignatureInfoValue(for: kSecCodeInfoTimestamp, from: info)

        } catch let error as WZSignatureError {
            self.statusDescription = error.description
            self.statusCode = error.code
            self.status = WZSignatureStatus(code: error.code)
        } catch {
        }
    }

    /**
     The signature details are gathered statically and the validation is performed using kSecCSStaticFlags

     - parameter path: The path of the file
     - parameter validate: Whether to validate the signature or not. If the
                           validation fails, the other attributes will be empty.
    */
    public init(path: String, validate: Bool=true) {
        do {
            let staticCode = try Self.getStaticCode(for: path)

            if validate {
                do {
                    try Self.validateStaticCode(staticCode)
                    try Self.checkFATSignaturesMatch(path: path)
                    self.status = .valid
                    self.isPlatformBinary = Self.isAppleSigned(staticCode: staticCode)
                } catch let error as WZSignatureError {
                    self.status = WZSignatureStatus(code: error.code)
                    self.statusCode = error.code
                    self.statusDescription = error.description
                } catch {}
            }

            let info = try Self.getSignatureInfo(staticCode, flags: kSecCSSigningInformation)

            self.format = Self.getSignatureInfoValue(for: kSecCodeInfoFormat, from: info)
            self.teamID = Self.getSignatureInfoValue(for: kSecCodeInfoTeamIdentifier, from: info)
            let mainExec: URL? = Self.getSignatureInfoValue(for: kSecCodeInfoMainExecutable, from: info)
            self.mainExecutable = mainExec?.path
            self.bundleID = Self.getSignatureInfoValue(for: kSecCodeInfoIdentifier, from: info)
            self.cdHash = Self.getCDHash(from: info)?.uppercased()
            self.certificates = Self.getCertificates(from: info)
            self.entitlements = Self.getSignatureInfoValue(for: kSecCodeInfoEntitlementsDict, from: info)
            if self.entitlements != nil {
                self.entitlements = self.filterDict(self.entitlements!)
            }
            self.flags = Self.getSignatureInfoValue(for: kSecCodeInfoFlags, from: info)
            self.signingDate = Self.getSignatureInfoValue(for: kSecCodeInfoTimestamp, from: info)

        } catch let error as WZSignatureError {
            self.statusDescription = error.description
            self.statusCode = error.code
            self.status = WZSignatureStatus(code: error.code)
        } catch {
        }
    }

    // Obtain the SecCode for an audit token
    static func getSecCode(for auditToken: Data) throws -> SecCode {
        var secCode: SecCode? = nil
        let status = SecCodeCopyGuestWithAttributes(nil, [
            kSecGuestAttributeAudit: auditToken
        ] as NSDictionary, SecCSFlags(rawValue: kSecCSDefaultFlags), &secCode)

        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }

        return secCode!
    }

    // Obtain the SecStaticCode for the given path
    static func getStaticCode(for path: String, flags: UInt32 = kSecCSDefaultFlags) throws -> SecStaticCode {
        let url = URL(fileURLWithPath: path)
        var staticCode: SecStaticCode? = nil
        let status = SecStaticCodeCreateWithPath(url as CFURL,
                                                 SecCSFlags(rawValue: flags), &staticCode)

        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }

        return staticCode!
    }

    /**
     Convinience method to obtain the SecStaticCode of an audit token

     The returned SecStaticCode will only refer to the architecture of the running code.
     If the running code belongs to a universal binary and all architectures are desired,
     then pass kSecCSUseAllArchitectures flag.
    */
    static func getStaticCode(for auditToken: Data, flags: UInt32 = kSecCSDefaultFlags) throws -> SecStaticCode {
        let secCode = try self.getSecCode(for: auditToken)
        return try self.getStaticCode(for: secCode, flags: flags)
    }

    /**
     Convert SecCode to SecStaticCode (its on-disk representation)

     The returned SecStaticCode will only refer to the architecture of the running code.
     If the running code belongs to a universal binary and all architectures are desired,
     then pass kSecCSUseAllArchitectures flag.
     */
    static func getStaticCode(for secCode: SecCode, flags: UInt32=kSecCSDefaultFlags) throws -> SecStaticCode {
        var staticCode: SecStaticCode? = nil
        let status = SecCodeCopyStaticCode(secCode, SecCSFlags(rawValue: flags), &staticCode)
        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }
        return staticCode!
    }

    // Validate the running code
    static func validateSecCode(_ secCode: SecCode, with req: SecRequirement?=nil) throws {
        let status = SecCodeCheckValidity(secCode, SecCSFlags(rawValue: kSecCSDefaultFlags), req)

        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }
    }

    /**
     Validate the static code on disk.

     This will check all architectures, nested code, won't validate resources and has network access disabled
     */
    static func validateStaticCode(_ staticCode: SecStaticCode, with req: SecRequirement?=nil) throws {
        let status = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStaticFlags), req)

        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }
    }

    /**
     Validate all architectures of a static code on disk.
     - parameter path: Path of the binary.
    */
    private static func checkFATSignaturesMatch(path: String) throws {
        let offsets = WZFile.getFATMachOSlices(path)

        var archInfos: [[CFString: Any]] = []
        for (_, offset) in offsets {
            var staticCode: SecStaticCode? = nil
            guard SecStaticCodeCreateWithPathAndAttributes(
                URL(fileURLWithPath: path) as CFURL,
                SecCSFlags(rawValue: kSecCSDefaultFlags),
                [
                    kSecCodeAttributeUniversalFileOffset: offset
                ] as NSDictionary,
                &staticCode) == errSecSuccess else {
                throw WZSignatureError(code: errSecCSNoSuchCode)
            }

            let info = try getSignatureInfo(staticCode!, flags: kSecCSSigningInformation)
            archInfos.append(info)
        }
        var leafCerts = Set<SecCertificate?>()
        // verify that all of the certificate identities are the same
        for info in archInfos {
            let flags: UInt32 = getSignatureInfoValue(for: kSecCodeInfoFlags, from: info) ?? 0

            // If signature is adhoc, add nil
            if (flags & SecCodeSignatureFlags.adhoc.rawValue) != 0 {
                leafCerts.insert(nil)
            } else {
                guard let certs: [SecCertificate] = getSignatureInfoValue(for: kSecCodeInfoCertificates, from: info),
                      let leaf = certs.first else {
                    // This should never happen technically
                    throw WZSignatureError(code: errSecInvalidCertificateRef)
                }
                leafCerts.insert(leaf)
            }
        }
        if leafCerts.count > 1 {
            throw WZSignatureError(code: errSecInvalidSignature)
        }
    }

    static func getPath(from auditToken: audit_token_t) -> String? {
        guard let secCode = try? Self.getSecCode(for: auditToken.data),
              let staticCode = try? Self.getStaticCode(for: secCode,
                                                       flags: kSecCSUseAllArchitectures) else {
            return nil
        }

        var path: CFURL? = nil
        if SecCodeCopyPath(staticCode, SecCSFlags(rawValue: kSecCSDefaultFlags), &path) != errSecSuccess {
            return nil
        }
        return (path! as URL).path
    }

    static func getRequirementFromString(_ req: String) -> SecRequirement! {
        var requirement: SecRequirement? = nil
        let status = SecRequirementCreateWithString(req as CFString, SecCSFlags(rawValue: kSecCSDefaultFlags), &requirement)
        guard status == errSecSuccess else {
            return nil
        }
        return requirement!
    }

    static func getSignatureInfo(_ staticCode: SecStaticCode, flags: UInt32) throws -> [CFString: Any] {
        var info: CFDictionary? = nil
        let status = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: flags), &info)
        guard status == errSecSuccess else {
            throw WZSignatureError(code: status)
        }
        return info as! [CFString: Any]
    }

    static func getSignatureInfoValue<T>(for key: CFString, from info: [CFString: Any]) -> T? {
        guard let value = info[key] as? T else {
            return nil
        }
        return value
    }

    static func getCDHash(from info: [CFString: Any]) -> String? {
        guard let hashData: Data = Self.getSignatureInfoValue(for: kSecCodeInfoUnique, from: info) else {
            return nil
        }

        return hashData.map { String(format: "%02hhx", $0) }.joined()
    }

    static func getCDHash(_ cdHash: (UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8,UInt8)) -> String {

        let byteArray = [cdHash.0, cdHash.1, cdHash.2, cdHash.3, cdHash.4, cdHash.5, cdHash.6, cdHash.7, cdHash.8, cdHash.9, cdHash.10, cdHash.11, cdHash.12, cdHash.13, cdHash.14, cdHash.15, cdHash.16, cdHash.17, cdHash.18, cdHash.19]

        return byteArray.map { String(format: "%02hhx", $0) }.joined()
    }

    static func getCertificates(from info: [CFString: Any]) -> [WZCertificate] {
        guard let certChain: [SecCertificate] = Self.getSignatureInfoValue(for: kSecCodeInfoCertificates, from: info) else {
            return []
        }

        return certChain.compactMap { try? WZCertificate($0) }
    }

    private func filterDict(_ dict: [String: Any]) -> [String: Any] {
        // Create a filtered dictionary
        var filteredDict = [String: Any]()

        for (key, value) in dict {
            if let nestedDict = value as? [String: Any] {
                // If the value is a CFDictionary, recursively filter it
                let nestedFilteredDict = filterDict(nestedDict)
                if !nestedFilteredDict.isEmpty {
                    filteredDict[key] = nestedFilteredDict
                }
            } else if value is String || value is Int || value is Array<String> || value is Bool
                      || value is Array<Int> || value is Array<Bool> {
                // Check if the value's type is one of the allowed types
                filteredDict[key] = value
            }
        }

        return filteredDict
    }

    public static func isAppleSigned(secCode: SecCode) -> Bool {
        do {
            try validateSecCode(secCode, with: kAppleRequirement)
            return true
        } catch {
            return false
        }
    }

    public static func isAppleSigned(staticCode: SecStaticCode) -> Bool {
        do {
            try validateStaticCode(staticCode, with: kAppleRequirement)
            return true
        } catch {
            return false
        }
    }

}

public struct WZSignatureError: Error, CustomStringConvertible {
    public let code: OSStatus

    public var description: String {
        return SecCopyErrorMessageString(code, nil) as? String ?? ""
    }
}

public enum WZSignatureStatus: String, Codable {
    case valid
    case invalid
    case unsigned
    case notFound
    case unknown

    public init(code: OSStatus) {
        switch code {
        case errSecSuccess:
            self = .valid
        case errSecCSUnsigned:
            self = .unsigned
        case Int32(kPOSIXErrorESRCH), errSecCSNoSuchCode, errSecCSStaticCodeNotFound:
            self = .notFound
        default:
            self = .invalid
        }
    }
}
