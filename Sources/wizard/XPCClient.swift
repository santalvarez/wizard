//
//  XPCClient.swift
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
import OSLog


class XPCClient {
    private static func getConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: APP_GROUP_ID, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: WZXPCAgentProtocol.self)
        connection.resume()
        return connection
    }

    private static func getAgentProxy() -> WZXPCAgentProtocol? {
        let connection = getConnection()

        return connection.remoteObjectProxyWithErrorHandler{ error in
            Logger.wizard.error("XPC Connection error \(error.localizedDescription, privacy: .public)")
            connection.invalidate()
            exit(1)
        } as? WZXPCAgentProtocol
    }
}
