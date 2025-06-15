//
// Copyright © 2025 Santiago Alvarez. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import Foundation
import NetworkExtension
import SwiftRuleEngine


@StringSubscriptable
public struct WZDNSReply: Encodable {
    public let status: UInt32
    public let header: WZDNSHeader
    public let question: [WZDNSQuestion]
    public let answer: [WZDNSResourceRecord]
    public let authority: [WZDNSResourceRecord]
    public let additional: [WZDNSResourceRecord]

    public var questionNames: [String] {
        return question.map { $0.name }
    }

    public init(_ reply: UnsafeMutablePointer<dns_reply_t>) {
        self.status = reply.pointee.status
        self.header = WZDNSHeader(reply.pointee.header)

        if self.header.qdcount != 0 {
            let questions = UnsafeBufferPointer(start: reply.pointee.question,
                                                count: Int(self.header.qdcount))
            self.question = questions.compactMap { WZDNSQuestion($0!) }
        } else { self.question = [] }

        if self.header.ancount != 0 {
            let answers = UnsafeBufferPointer(start: reply.pointee.answer,
                                              count: Int(self.header.ancount))
            self.answer = answers.compactMap { WZDNSResourceRecord($0!) }
        } else { self.answer = [] }

        if self.header.nscount != 0 {
            let authorities = UnsafeBufferPointer(start: reply.pointee.authority,
                                                  count: Int(self.header.nscount))
            self.authority = authorities.compactMap { WZDNSResourceRecord($0!) }
        } else { self.authority = [] }

        if self.header.arcount != 0 {
            let additionals = UnsafeBufferPointer(start: reply.pointee.additional,
                                                  count: Int(self.header.arcount))
            self.additional = additionals.compactMap { WZDNSResourceRecord($0!) }
        } else { self.additional = [] }
    }

}

@StringSubscriptable
public struct WZDNSHeader: Encodable {
    public let xid: UInt16
    public let flags: UInt16
    public let qdcount: UInt16
    public let ancount: UInt16
    public let nscount: UInt16
    public let arcount: UInt16

    public init(_ header: UnsafeMutablePointer<dns_header_t>) {
        self.xid = header.pointee.xid
        self.flags = header.pointee.flags
        self.qdcount = header.pointee.qdcount
        self.ancount = header.pointee.ancount
        self.nscount = header.pointee.nscount
        self.arcount = header.pointee.arcount
    }
}

@StringSubscriptable(withKeys: false)
public struct WZDNSQuestion: Encodable {
    public let name: String
    public let type: WZDNSType
    public let `class`: UInt16

    public init(_ question: UnsafeMutablePointer<dns_question_t>) {
        self.name = String(cString: question.pointee.name)
        self.type = WZDNSType(Int(question.pointee.dnstype))
        self.class = question.pointee.dnsclass
    }

    private static let keys: [String: PartialKeyPath<WZDNSQuestion>] = [
        "name": \.name,
        "type": \.type.rawValue,
        "class": \.class
    ]
}

public enum WZDNSType: String, Encodable {
    case A
    case AAAA
    case CNAME
    case TXT
    case SOA
    case MX
    case SRV
    case NS
    case PTR
    case UNKNOWN

    public init(_ type: Int) {
        switch type {
        case kDNSServiceType_A:  // ipv4
            self = .A
        case kDNSServiceType_AAAA:  // ipv6
            self = .AAAA
        case kDNSServiceType_CNAME:
            self = .CNAME
        case kDNSServiceType_TXT:
            self = .TXT
        case kDNSServiceType_SOA:
            self = .SOA
        case kDNSServiceType_MX:
            self = .MX
        case kDNSServiceType_SRV:
            self = .SRV
        case kDNSServiceType_NS:
            self = .NS
        case kDNSServiceType_PTR:
            self = .PTR
        default:
            self = .UNKNOWN
        }
    }
}

@StringSubscriptable
public struct WZDNSResourceRecord: Encodable {
    public let name: String
    public let type: WZDNSType
    public let `class`: UInt16
    public let ttl: UInt32
    public let data: WZDNSRecordProtocol

    public init?(_ resource: UnsafeMutablePointer<dns_resource_record_t>) {
        self.name = String(cString: resource.pointee.name)
        self.type = WZDNSType(Int(resource.pointee.dnstype))
        self.class = resource.pointee.dnsclass
        self.ttl = resource.pointee.ttl

        switch self.type {
        case .A:  // ipv4
            self.data = WZDNSRecordA(resource.pointee.data.A)
        case .AAAA:  // ipv6
            self.data = WZDNSRecordA(resource.pointee.data.AAAA)
        case .CNAME:
            self.data = WZDNSRecordDomainName(resource.pointee.data.CNAME)
        case .TXT:
            self.data = WZDNSRecordTXT(resource.pointee.data.TXT)
        case .SOA:
            self.data = WZDNSRecordSOA(resource.pointee.data.SOA)
        case .MX:
            self.data = WZDNSRecordMX(resource.pointee.data.MX)
        case .SRV:
            self.data = WZDNSRecordSRV(resource.pointee.data.SRV)
        case .NS:
            self.data = WZDNSRecordDomainName(resource.pointee.data.NS)
        case .PTR:
            self.data = WZDNSRecordDomainName(resource.pointee.data.PTR)
        default:
            return nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(type, forKey: .type)
        try container.encode(`class`, forKey: .`class`)
        try container.encode(ttl, forKey: .ttl)
        try container.encode(data, forKey: .data)
    }

    enum CodingKeys: String, CodingKey {
        case name
        case type
        case `class`
        case ttl
        case data
    }
}

public protocol WZDNSRecordProtocol: Encodable {
}

@StringSubscriptable
public struct WZDNSRecordA: WZDNSRecordProtocol {
    public let addr: String

    public init(_ record: UnsafeMutablePointer<dns_address_record_t>) {
        self.addr = record.pointee.addr.description
    }

    public init(_ record: UnsafeMutablePointer<dns_in6_address_record_t>) {
        self.addr = record.pointee.addr.description
    }
}

@StringSubscriptable
public struct WZDNSRecordMX: WZDNSRecordProtocol {
    public let name: String
    public let preference: UInt16

    public init(_ record: UnsafeMutablePointer<dns_MX_record_t>) {
        self.name = String(cString: record.pointee.name)
        self.preference = record.pointee.preference
    }
}

@StringSubscriptable
public struct WZDNSRecordSOA: WZDNSRecordProtocol {
    public let serial: UInt32
    public let refresh: UInt32
    public let retry: UInt32
    public let expire: UInt32
    public let minimum: UInt32
    public let rname: String
    public let mname: String

    public init(_ record: UnsafeMutablePointer<dns_SOA_record_t>) {
        self.serial = record.pointee.serial
        self.refresh = record.pointee.refresh
        self.retry = record.pointee.retry
        self.expire = record.pointee.expire
        self.minimum = record.pointee.minimum
        self.rname = String(cString: record.pointee.rname)
        self.mname = String(cString: record.pointee.mname)
    }
}

@StringSubscriptable
public struct WZDNSRecordTXT: WZDNSRecordProtocol {
    public let strings: [String]

    public init(_ record: UnsafeMutablePointer<dns_TXT_record_t>) {
        var strArray: [String] = []
        guard record.pointee.string_count > 0 else {
            self.strings = []
            return
        }
        for index in 0...Int(record.pointee.string_count - 1) {
            guard let txtItem = record.pointee.strings[index] else {
                continue
            }

            strArray.append(String(cString: txtItem))
        }
        self.strings = strArray
    }
}

@StringSubscriptable
public struct WZDNSRecordSRV: WZDNSRecordProtocol {
    public let port: UInt16
    public let priority: UInt16
    public let weight: UInt16
    public let target: String

    public init(_ record: UnsafeMutablePointer<dns_SRV_record_t>) {
        self.port = record.pointee.port
        self.priority = record.pointee.priority
        self.weight = record.pointee.weight
        self.target = String(cString: record.pointee.target)
    }
}

@StringSubscriptable
public struct WZDNSRecordDomainName: WZDNSRecordProtocol {
    public let name: String

    public init(_ record: UnsafeMutablePointer<dns_domain_name_record_t>) {
        self.name = String(cString: record.pointee.name)
    }
}
