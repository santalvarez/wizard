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
import CryptoKit
import SwiftRuleEngine


@StringSubscriptable(withKeys: true)
public struct WZCertificate: Codable, Hashable {

    enum InitError: Error {
        case failedToFindValue(key: String)
        case failedToCastValue(expected: String, actual: String)
        case failedToFindLabel(label: String)
        case failedToCopyValues
    }
    public let sha256: String
    public let isCA: Bool

    public let validFrom: Double
    public let validUntil: Double

    public let issuerCommonName: String
    public let issuerCountryName: String
    public let issuerOrgName: String
    public let issuerOrgUnit: String

    public let commonName: String?
    public let countryName: String?
    public let orgName: String?
    public let orgUnit: String?

    public init(_ cert: SecCertificate) throws {
        let data = SecCertificateCopyData(cert) as Data
        guard let results = SecCertificateCopyValues(cert, nil, nil) as? [CFString: Any] else {
            throw InitError.failedToCopyValues
        }

        commonName = Self.getCommonName(for: cert)
        sha256 = SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()

        validFrom = Date(timeIntervalSinceReferenceDate: try Self.getValue(for: kSecOIDX509V1ValidityNotBefore, from: results)).timeIntervalSince1970
        validUntil = Date(timeIntervalSinceReferenceDate: try Self.getValue(for: kSecOIDX509V1ValidityNotAfter, from: results)).timeIntervalSince1970

        let basicConstraints: [[CFString: Any]] = try Self.getValue(for: kSecOIDBasicConstraints, from: results)

        isCA = (try Self.getValue(for: "Certificate Authority" as CFString, fromDict: basicConstraints) as NSString).boolValue

        let issuerName: [[CFString: Any]] = try Self.getValue(for: kSecOIDX509V1IssuerName, from: results)
        issuerCommonName = try Self.getValue(for: kSecOIDCommonName, fromDict: issuerName)
        issuerCountryName = try Self.getValue(for: kSecOIDCountryName, fromDict: issuerName)
        issuerOrgName = try Self.getValue(for: kSecOIDOrganizationName, fromDict: issuerName)
        issuerOrgUnit = try Self.getValue(for: kSecOIDOrganizationalUnitName, fromDict: issuerName)

        let subjectName: [[CFString: Any]] = try Self.getValue(for: kSecOIDX509V1SubjectName, from: results)
        countryName = try Self.getValue(for: kSecOIDCountryName, fromDict: subjectName)
        orgName = try? Self.getValue(for: kSecOIDOrganizationName, fromDict: subjectName)
        orgUnit = try? Self.getValue(for: kSecOIDOrganizationalUnitName, fromDict: subjectName)
    }

    private static func getValue<T>(for key: CFString, from values: [CFString: Any]) throws -> T {
        let node = values[key] as? [CFString: Any]

        guard let rawValue = node?[kSecPropertyKeyValue] else {
            throw InitError.failedToFindValue(key: key as String)
        }

        if T.self is Date.Type {
            if let value = rawValue as? TimeInterval {
                // Force unwrap here is fine as we've validated the type above
                return Date(timeIntervalSinceReferenceDate: value) as! T
            }
        }

        guard let value = rawValue as? T else {
            let type = (node?[kSecPropertyKeyType] as? String) ?? String(describing: rawValue)
            throw InitError.failedToCastValue(expected: String(describing: T.self), actual: type)
        }

        return value
    }

    private static func getValue<T>(for key: CFString, fromDict values: [[CFString: Any]]) throws -> T {

        guard let results = values.first(where: { ($0[kSecPropertyKeyLabel] as? String) == (key as String) }) else {
            throw InitError.failedToFindLabel(label: key as String)
        }

        guard let rawValue = results[kSecPropertyKeyValue] else {
            throw InitError.failedToFindValue(key: key as String)
        }

        guard let value = rawValue as? T else {
            let type = (results[kSecPropertyKeyType] as? String) ?? String(describing: rawValue)
            throw InitError.failedToCastValue(expected: String(describing: T.self), actual: type)
        }

        return value
    }

    private static func getCommonName(for cert: SecCertificate) -> String? {
        var commonName: CFString? = nil
        guard SecCertificateCopyCommonName(cert, &commonName) == errSecSuccess else {
            return nil
        }
        return commonName as? String
    }
}
