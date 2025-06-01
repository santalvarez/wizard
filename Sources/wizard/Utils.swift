//
//  Utils.swift
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

struct Utils {
    static func runCommand(commandPath:String, arguments:[String]? = nil) throws -> String{
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = URL(fileURLWithPath:commandPath)
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        if arguments != nil{
            process.arguments = arguments
        }

        try process.run()
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data:data, encoding: String.Encoding.utf8)!
        return output
    }

}
