//
//  WZEncoder.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation



final class WZEncoder: JSONEncoder, @unchecked Sendable {
    init(encodeProcessParent: Bool) {
        super.init()
        self.keyEncodingStrategy = .convertToSnakeCase
        self.dateEncodingStrategy = .secondsSince1970
    }

    static let shared = WZEncoder(encodeProcessParent: true)
}
