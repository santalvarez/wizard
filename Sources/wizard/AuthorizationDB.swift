//
//  AuthorizationDB.swift
//  wizard
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import Foundation
import Security
import OSLog


struct AuthorizationDB {
    enum Error: Swift.Error {
        case authorizationError(String)
    }

    /// Wrapper to handle possible errors of authorization functions
    private static func runAuthorizationFunction(_ authorizationFunction: () -> OSStatus) throws {
		let status = authorizationFunction()

        guard status == errAuthorizationSuccess else {
            throw Error.authorizationError(String(describing: SecCopyErrorMessageString(status, nil)))
        }
    }

    /// Returns a new authorization reference
    private static func createAuthorizationRef(_ rights: UnsafePointer<AuthorizationRights>?,
                                               _ environment: UnsafePointer<AuthorizationEnvironment>?,
                                               _ flags: AuthorizationFlags) throws -> AuthorizationRef {
        var authRef: AuthorizationRef?

        try runAuthorizationFunction { AuthorizationCreate(rights, environment, flags, &authRef) }

        return authRef!
    }

    /// Returns a rights definition in the form of `CFDictionary`
    private static func getRightDefinition(_ rightName: String) throws -> CFDictionary {
        var rightDefinition: CFDictionary?
        try runAuthorizationFunction { AuthorizationRightGet(rightName, &rightDefinition) }

        return rightDefinition!
    }

    /// Set a rights definition
    private static func setRightDefinition(_ rightName: String, _ rightDefinition: CFDictionary, _ description: String?) throws {
        let authRef = try createAuthorizationRef(nil, nil, [])

        try runAuthorizationFunction { AuthorizationRightSet(authRef, rightName, rightDefinition, description as CFString?, nil, nil) }
    }

    /// Adds the rule `is-root` to the `com.apple.system-extensions.admin` right if not already there
    static func setSysExtAdminRightToRoot() throws {
        let rightDef: CFDictionary = try getRightDefinition("com.apple.system-extensions.admin")

        guard var rightDefDict = rightDef as? [String: AnyObject] else {
            return
        }

        rightDefDict["rule"] = ["is-root"] as AnyObject

		try setRightDefinition("com.apple.system-extensions.admin", rightDefDict as CFDictionary, nil)
    }

    /// Restores `com.apple.system-extensions.admin` right to its default setting
    static func restoreSysExtAdminRight() throws {
        let rightDef: CFDictionary = try getRightDefinition("com.apple.system-extensions.admin")

        guard var rightDefDict = rightDef as? [String: AnyObject] else {
            return
        }

        rightDefDict["rule"] = ["authenticate-admin-nonshared"] as AnyObject

		try setRightDefinition("com.apple.system-extensions.admin", rightDefDict as CFDictionary, nil)
    }

}
