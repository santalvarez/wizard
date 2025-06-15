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


/// Provides thread safety to the wrapped type
@propertyWrapper
public final class Atomic<Value> {
    private var _value: Value
    private let lock = NSLock()

    public init(wrappedValue: Value) {
        self._value = wrappedValue
    }

    var wrappedValue: Value {
        get {
            lock.lock()
            defer { lock.unlock() }
            return self._value
        }
        set(newValue) {
            lock.withLock { self._value = newValue }
        }
    }

    /// Thread-safe updates of value.
    func mutate(_ transform: (inout Value) -> Void) {
        self.lock.withLock {
            transform(&self._value)
        }
    }
}

extension Atomic: Encodable where Value: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.wrappedValue)
    }
}

@propertyWrapper
public final class LazyAtomic<Value> {
    private var initializer: () -> Value
    private var value: Value?
    private let lock = NSLock()
    private var isInitialized = false

    public init(wrappedValue initializer: @autoclosure @escaping () -> Value) {
        self.initializer = initializer
    }

    var wrappedValue: Value {
        get {
            lock.lock()
            defer { lock.unlock() }

            if !isInitialized {
                self.value = initializer()
                self.isInitialized = true
            }

            return self.value!
        }
        set(newValue) {
            lock.withLock {
                self.value = newValue
            }
        }
    }
}

extension LazyAtomic: Encodable where Value: Encodable {
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.wrappedValue)
    }
}

