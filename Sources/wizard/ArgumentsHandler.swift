//
//  ArgumentsHandler.swift
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

/**
 An object that contains different actions to take from provided command line arguments.
 Arguments should be parsed in AppDelegate and from there call this object.
 At the end of every function's execution there should be an `exit` call to prevent the cli from stalling.
 */
struct ArgumentsHandler {
    /// Prints help message of command line arguments
    static func printArgsHelp() {
        let help = """
            USAGE: args [--load-agent] [--unload-agent]
            OPTIONS:
              --load-agent   Load the Agent (root)
              --unload-agent Unload the Agent (root)
              --help                    Show help information

            """
        print(help)
        exit(0)
    }

    static func unloadAgent() {
        checkRoot()
        print("Unloading System Extension")
        SystemExtensionHandler.shared.deactivateExtension(.Unload)
    }

    static func loadAgent() {
        checkRoot()
        print("Loading System Extension")
        SystemExtensionHandler.shared.activateExtension()
    }

    /// Checks if running as root, if we are not it exits
    private static func checkRoot() {
        guard getuid() == 0 else {
            print("Need to run as root. Exiting...")
            exit(1)
        }
    }

}
