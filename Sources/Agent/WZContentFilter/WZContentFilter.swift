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

 import NetworkExtension
 import EndpointSecurity
 import OSLog

class WZContentFilter: NEFilterDataProvider {
    private let queue = DispatchQueue(label: "com.santalvarez.wizard.Agent.WZContentFilter",
                                                     qos: .userInitiated, attributes: .concurrent)

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        var rules: [NEFilterRule] = []

        let rule: NENetworkRule
        if #available(macOS 15.0, *) {
            rule = NENetworkRule(remoteNetworkEndpoint: nil,
                                 remotePrefix: 0,
                                 localNetworkEndpoint: nil,
                                 localPrefix: 0,
                                 protocol: .any,
                                 direction: .any)
        } else {
            rule = NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .any
            )
        }

         let filterRule = NEFilterRule(networkRule: rule, action: .filterData)

         rules = [filterRule]

         // Allow all flows that do not match the filter rules.
         let filterSettings = NEFilterSettings(rules: rules, defaultAction: .allow)

         apply(filterSettings) { error in
             if let applyError = error {
                 Logger.Agent.error("Failed to apply filter settings: \(applyError.localizedDescription)")
             }
             completionHandler(error)
         }
     }

     override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
         completionHandler()
     }

     override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
         let eventStartTime = WZUtils.currentMachTimeNano()

         guard let flow = flow as? NEFilterSocketFlow,
               let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
             return .allow()
         }

         if remoteEndpoint.port == "53" && flow.direction == .outbound {
             return .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 512, filterOutbound: false, peekOutboundBytes: 0)
         }

         let timestamp = Date().timeIntervalSince1970

         // We use a semaphore because resuming a flow that is not paused is invalid (per docs)
         let semaphore = DispatchSemaphore(value: 0)

         queue.async {
             let event = WZEvent(flow, timestamp)
//             let result = eventHandler.handle(event)
//             semaphore.wait()
//             self.resumeFlow(flow, with: result.verdict.toNENewFlowVerdict())
//             metricsHandler.recordEvent(event.eventType, WZUtils.currentMachTimeNano() - eventStartTime)
//             eventPostProcessor.process(result)
         }
         semaphore.signal()
         return .pause()
     }

     /// NOTE: Currently this is used only to handle DNS response data
     override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
         let eventStartTime = WZUtils.currentMachTimeNano()

         guard let flow = flow as? NEFilterSocketFlow else {
             return .allow()
         }

         let timestamp = Date().timeIntervalSince1970

         let semaphore = DispatchSemaphore(value: 0)

         queue.async {
             let event = WZEvent(flow, timestamp, readBytes)
//             let result = eventHandler.handle(event)
//             semaphore.wait()
//             self.resumeFlow(flow, with: result.verdict.toNEFilterDataVerdict())
//             metricsHandler.recordEvent(event.eventType, WZUtils.currentMachTimeNano() - eventStartTime)
//             eventPostProcessor.process(result)
         }
         semaphore.signal()
         return .pause()
     }
 }
