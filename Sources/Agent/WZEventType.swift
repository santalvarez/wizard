// Copyright 2025 Santiago Alvarez.
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
import EndpointSecurity


public enum WZEventClass: String, Encodable {
    case es
    case ne
}

public enum WZEventType: String, Encodable, CaseIterable, CodingKeyRepresentable {
    // Endpoint Security Events
    case es_exec
    case es_fork
    case es_create
    case es_mount
    case es_unmount
    case es_remount
    case es_exit
    case es_authentication
    case es_authorization_petition
    case es_xp_malware_detected
    case es_xp_malware_remediated
    case es_login
    case es_logout
    case es_screensharing_attach
    case es_screensharing_detach
    case es_cs_invalidated
    case es_btm_launch_item_add
    case es_btm_launch_item_remove

    // Network Events
    case ne_inbound
    case ne_outbound
    case ne_dns_reply

    case unknown

    public static var allESCases: [WZEventType] {
        return WZEventType.allCases.filter { $0.rawValue.starts(with: "es_") }
    }

    public static var allFWCases: [WZEventType] {
        return WZEventType.allCases.filter { $0.rawValue.starts(with: "ne_") }
    }

    public init(_ es_event_type: es_event_type_t) {
        switch es_event_type {
        case ES_EVENT_TYPE_AUTH_EXEC,
             ES_EVENT_TYPE_NOTIFY_EXEC:
            self = .es_exec
        case ES_EVENT_TYPE_NOTIFY_FORK:
            self = .es_fork
        case ES_EVENT_TYPE_AUTH_CREATE,
             ES_EVENT_TYPE_NOTIFY_CREATE:
            self = .es_create
        case ES_EVENT_TYPE_AUTH_MOUNT,
             ES_EVENT_TYPE_NOTIFY_MOUNT:
            self = .es_mount
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            self = .es_unmount
        case ES_EVENT_TYPE_AUTH_REMOUNT,
             ES_EVENT_TYPE_NOTIFY_REMOUNT:
            self = .es_remount
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            self = .es_exit
        case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
            self = .es_authentication
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            self = .es_authorization_petition
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            self = .es_xp_malware_detected
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            self = .es_xp_malware_remediated
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            self = .es_login
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
            self = .es_logout
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
            self = .es_screensharing_attach
        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
            self = .es_screensharing_detach
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            self = .es_cs_invalidated
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            self = .es_btm_launch_item_add
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            self = .es_btm_launch_item_remove
        default:
            self = .unknown
        }
    }
}

