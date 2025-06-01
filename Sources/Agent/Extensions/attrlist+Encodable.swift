//
//  attrlist+Encodable.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation


extension attrlist: Encodable {
    static private let keys: [String: PartialKeyPath<Self>] = [
        "bitmapcount": \.bitmapcount,
        "commonattr": \.commonattr,
        "volattr": \.volattr,
        "dirattr": \.dirattr,
        "fileattr": \.fileattr,
        "forkattr": \.forkattr
    ]

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(bitmapcount, forKey: .bitmapcount)
        try container.encode(commonattr, forKey: .commonattr)
        try container.encode(volattr, forKey: .volattr)
        try container.encode(dirattr, forKey: .dirattr)
        try container.encode(fileattr, forKey: .fileattr)
        try container.encode(forkattr, forKey: .forkattr)
    }

    enum CodingKeys: String, CodingKey {
        case bitmapcount, commonattr, volattr, dirattr, fileattr, forkattr
    }
}
