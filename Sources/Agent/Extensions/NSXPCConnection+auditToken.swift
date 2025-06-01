//
//  NSXPCConnection+auditToken.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation

extension NSXPCConnection {
    /**
    Exposes the **private** audit token data of the connection.

    Adapted from: [AuditTokenHack](https://github.com/securing/SimpleXPCApp/blob/master/SimpleXPCService/AuditTokenHack.m)

    SeeAlso:
    - [Convert NSValue to NSData](https://stackoverflow.com/a/8451337/6053417)
    - [The Story Behind CVE-2019-13013](https://blog.obdev.at/what-we-have-learned-from-a-vulnerability/)
    */
    public var auditToken: Data {
        guard self.responds(to: Selector(("auditToken"))) else {
            return Data()
        }

        guard let value = self.value(forKey: "auditToken") as? NSValue else {
            return Data()
        }

        var size: Int = 0
        NSGetSizeAndAlignment(value.objCType, &size, nil)

        guard let tmp = malloc(size) else {
            return Data()
        }
        defer { free(tmp) }
        value.getValue(tmp)

        return Data(bytes: tmp, count: size)
    }
}
