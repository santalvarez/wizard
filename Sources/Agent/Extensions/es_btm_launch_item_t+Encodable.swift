//
//  es_btm_launch_item_t+Encodable.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import EndpointSecurity
import SwiftRuleEngine



extension es_btm_launch_item_t: Encodable, StringSubscriptable {
    static private let keys: [String: PartialKeyPath<Self>] = [
        "app_url": \.app_url.description,
        "item_url": \.item_url,
        "legacy": \.legacy,
        "managed": \.managed,
        "uid": \.uid,
        "item_type": \.item_type.rawValue
    ]

    public subscript(key: String) -> Any? {
        guard let kp = Self.keys[key] else {
            return nil
        }
        return self[keyPath: kp]
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.app_url.description, forKey: .app_url)
        try container.encode(self.item_url.description, forKey: .item_url)
        try container.encode(self.legacy, forKey: .legacy)
        try container.encode(self.managed, forKey: .managed)
        try container.encode(self.uid, forKey: .uid)
        try container.encode(self.item_type.rawValue, forKey: .item_type)
    }

    enum CodingKeys: String, CodingKey {
        case app_url, item_url, legacy, managed, uid, item_type
    }
}
