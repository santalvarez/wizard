//
//  Logger+.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import CryptoKit
import OSLog
import EndpointSecurity
import NetworkExtension


extension Logger {
    static let subsystem = "com.santalvarez.wizard.Agent"
    static let Agent = Logger(subsystem: subsystem, category: "default")
}
