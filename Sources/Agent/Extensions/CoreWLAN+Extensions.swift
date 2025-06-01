//
//  CoreWLAN+Extensions.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import CoreWLAN



extension CWInterfaceMode {
    public var description: String {
        switch(self) {
        case .hostAP:  return "AP";
        case .IBSS:    return "Adhoc";
        case .station: return "Station";
        case .none:    return "none";
        @unknown default:
            return "unknown"
        }
    }
}

extension CWSecurity {
    public var description: String {
        switch(self) {
        case .none:               return "none";
        case .unknown:            return "unknown";
        case .WEP:                return "WEP";
        case .wpaPersonal:        return "WPA Personal";
        case .wpaPersonalMixed:   return "WPA Personal Mixed";
        case .wpa2Personal:       return "WPA2 Personal";
        case .wpa2Enterprise:     return "WPA2 Enterprise";
        case .personal:           return "Personal";
        case .dynamicWEP:         return "Dynamic WEP";
        case .wpaEnterprise:      return "WPA Enterprise";
        case .wpaEnterpriseMixed: return "WPA Enterprise Mixed";
        case .enterprise:         return "Enterprise";
        case .wpa3Enterprise:     return "WPA3 Enterprise"
        case .wpa3Personal:       return "WPA3 Personal"
        case .wpa3Transition:     return "WPA3 Transition"
        case .OWE:                return "OWE"
        case .oweTransition:      return "OWE Transition"
        @unknown default:
            return "unknown"
        }
    }
}

extension CWChannelBand {
    public var toInt: Int {
        switch(self) {
        case .band2GHz: return 2
        case .band5GHz: return 5
        case .band6GHz: return 6
        case .bandUnknown: return -1
        @unknown default:
            return -1
        }
    }
}

extension CWChannelWidth {
    public var toInt: Int {
        switch(self) {
        case .width20MHz: return 20
        case .width40MHz: return 40
        case .width80MHz: return 80
        case .width160MHz: return 160
        case .widthUnknown: return -1
        @unknown default:
            return -1
        }
    }
}
