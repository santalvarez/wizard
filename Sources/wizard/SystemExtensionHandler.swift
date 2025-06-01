//
//  SystemExtensionHandler.swift
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
import SystemExtensions
import NetworkExtension
import OSLog

enum SystemExtensionAction {
    case Load
    case Unload
}


class SystemExtensionHandler {
    private let loadDelegate = ExtensionRequestDelegate(.Load)
    private let unloadDelegate =  ExtensionRequestDelegate(.Unload)
    static let shared = SystemExtensionHandler()

    func extensionBundle() -> Bundle {

        let extensionsDirectoryURL = URL(fileURLWithPath: "Contents/Library/SystemExtensions", relativeTo: Bundle.main.bundleURL)
        let extensionURLs: [URL]
        do {
            extensionURLs = try FileManager.default.contentsOfDirectory(at: extensionsDirectoryURL,
                                                                        includingPropertiesForKeys: nil,
                                                                        options: .skipsHiddenFiles)
        } catch let error {
            fatalError("Failed to get the contents of \(extensionsDirectoryURL.absoluteString): \(error.localizedDescription)")
        }

        guard let extensionURL = extensionURLs.first else {
            fatalError("Failed to find any system extensions")
        }

        guard let extensionBundle = Bundle(url: extensionURL) else {
            fatalError("Failed to create a bundle with URL \(extensionURL.absoluteString)")
        }

        return extensionBundle
    }

    /// Submits the system extension activation request
    func activateExtension() {
        guard let extensionIdentifier = extensionBundle().bundleIdentifier else {
            return
        }

        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self.loadDelegate
        OSSystemExtensionManager.shared.submitRequest(request)
        Logger.wizard.log("System Extension Activation Request Sent")
        print("System Extension Activation Request Sent")
    }

    /// Submits the system extension deactivation request
    func deactivateExtension(_ action: SystemExtensionAction) {
        guard let extensionIdentifier = extensionBundle().bundleIdentifier else {
            return
        }

        do {
            try AuthorizationDB.setSysExtAdminRightToRoot()
        } catch {
            print(error.localizedDescription)
            Logger.wizard.error("\(error.localizedDescription)")
            exit(1)
        }

        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self.unloadDelegate
        OSSystemExtensionManager.shared.submitRequest(request)
        Logger.wizard.log("System Extension Deactivation Request Sent")
        print("System Extension Deactivation Request Sent")
    }

}

class ExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private var action: SystemExtensionAction

    init(_ action: SystemExtensionAction) {
        self.action = action
    }

    // SYSTEM EXTENSION SUCCESS
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
			print("System Extension request completed successfully")
            Logger.wizard.log("System extension request completed successfully")
        case .willCompleteAfterReboot:
            print("System Extension request will complete after reboot")
            Logger.wizard.log("System extension request will complete after reboot")
        @unknown default:
            print("System Extension request unknown result \(result.rawValue)")
            Logger.wizard.error("System extension request unknown result \(result.rawValue)")
            exit(1)
        }

        // Restore System Extension Admin right after unloading
        if action == .Unload {
            do {
                try AuthorizationDB.restoreSysExtAdminRight()
            } catch {
                print(error.localizedDescription)
                Logger.wizard.error("\(error.localizedDescription)")
            }
        }

        self.toggleFilterConfiguration(action) { status in
            exit(status)
        }
    }

    // SYSTEM EXTENSION FAILED
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("System Extension request failed: \(error.localizedDescription)")
        Logger.wizard.error("System extension request failed: \(error.localizedDescription, privacy: .public)")

        if action == .Unload {
            do {
                try AuthorizationDB.restoreSysExtAdminRight()
            } catch {
                print(error.localizedDescription)
                Logger.wizard.error("\(error.localizedDescription)")
            }
        }
        // NOTE: Better handle errors
        exit(0)
    }

    // SYSTEM EXTENSION REQUIRES APPROVAL
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
		print("System Extension requires user approval")
        Logger.wizard.log("System Extension requires user approval")
    }

    // SYSTEM EXTENSION REPLACE
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension extension: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("Replacing extension \(request.identifier) version \(existing.bundleShortVersion) with version \(`extension`.bundleShortVersion)")
        Logger.wizard.log("Replacing extension \(request.identifier, privacy: .public) version \(existing.bundleShortVersion, privacy: .public) with version \(`extension`.bundleShortVersion, privacy: .public)")
        return .replace
    }

    func loadFilterConfiguration(completion: @escaping (Bool) -> Void) {
        NEFilterManager.shared().loadFromPreferences { loadError in
            DispatchQueue.main.async {
                var success = true
                if let error = loadError {
                    print("Failed to load the filter configuration \(error.localizedDescription)")
                    Logger.wizard.error("Failed to load the filter configuration \(error.localizedDescription, privacy: .public)")
                    success = false
                }
                completion(success)
            }
        }
    }

    func toggleFilterConfiguration(_ action: SystemExtensionAction, completion: @escaping (Int32) -> Void) {
        if action == .Load {
            Logger.wizard.log("Enabling filter configuration")
        } else {
            Logger.wizard.log("Disabling filter configuration")
        }

        let filterManager = NEFilterManager.shared()

        self.loadFilterConfiguration { success in
            guard success else {
                completion(1)
                return
            }

            if action == .Load {
                if filterManager.providerConfiguration == nil {
                    let providerConfiguration = NEFilterProviderConfiguration()
                    providerConfiguration.organization = "Wizard"
                    providerConfiguration.filterDataProviderBundleIdentifier = "com.santalvarez.wizard.Agent"
                    providerConfiguration.filterSockets = true // filtering at flow layer
                    providerConfiguration.filterPackets = false
                    filterManager.providerConfiguration = providerConfiguration
                    filterManager.localizedDescription = "Wizard"
                }
                filterManager.isEnabled = true
            } else {
                filterManager.isEnabled = false
            }

            filterManager.saveToPreferences { saveError in
                DispatchQueue.main.async {
                    if let error = saveError {
                        Logger.wizard.error("Failed to save the filter configuration \(error.localizedDescription, privacy: .public)")
                    }
                    completion(0)
                    return
                }
            }
        }
    }
}
