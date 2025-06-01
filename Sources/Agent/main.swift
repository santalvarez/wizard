//
//  main.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import OSLog
import NetworkExtension

Logger.Agent.log("Starting Wizard Agent")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
