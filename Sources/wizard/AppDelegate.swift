//
//  AppDelegate.swift
//  wizard
//
//  Created by Santiago Alvarez on 03/08/2020.
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

import Cocoa
import OSLog

extension Logger {
    private static let subsystem = "com.santalvarez.wizard"

    static let wizard = Logger(subsystem: subsystem, category: "default")
}

@NSApplicationMain // Makes AppDelegate the main entry point
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let args = CommandLine.arguments

        if args.contains("--help") || args.count == 1 {
            ArgumentsHandler.printArgsHelp()

        } else if args.contains("--load-agent") {
            ArgumentsHandler.loadAgent()

        } else if args.contains("--unload-agent") {
            ArgumentsHandler.unloadAgent()

        } else {
            exit(1)
        }
    }
}
