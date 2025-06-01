//
//  LRUCache.swift
//  LRUCache
//
//  Version 1.0.2
//
//  Created by Nick Lockwood on 05/08/2021.
//  Copyright © 2021 Nick Lockwood. All rights reserved.
//
//  Distributed under the permissive MIT license
//  Get the latest version from here:
//
//  https://github.com/nicklockwood/LRUCache
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import Foundation

/// Notification that cache should be cleared
public let LRUCacheMemoryWarningNotification: NSNotification.Name =
    .init("LRUCacheMemoryWarningNotification")


public final class LRUCache<Key: Hashable, Value> {
    private var values: [Key: Container] = [:]
    private unowned(unsafe) var head: Container?
    private unowned(unsafe) var tail: Container?
    private let lock: NSLock = .init()
    private var token: AnyObject?
    private let notificationCenter: NotificationCenter
    private let dateProvider: () -> Date


    /// The current total cost of values in the cache
    public private(set) var totalCost: Int = 0

    /// The maximum total cost permitted
    public var totalCostLimit: Int {
        didSet { clean() }
    }

    /// The maximum number of values permitted
    public var countLimit: Int {
        didSet { clean() }
    }

    /// Initialize the cache with the specified `totalCostLimit` and `countLimit`
    public init(
        totalCostLimit: Int = .max,
        countLimit: Int = .max,
        notificationCenter: NotificationCenter = .default,
        dateProvider: @escaping () -> Date = Date.init
    ) {
        self.totalCostLimit = totalCostLimit
        self.countLimit = countLimit
        self.notificationCenter = notificationCenter
        self.dateProvider = dateProvider

        self.token = notificationCenter.addObserver(
            forName: LRUCacheMemoryWarningNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.emptyCache()
        }
    }

    deinit {
        if let token = token {
            notificationCenter.removeObserver(token)
        }
    }
}

public extension LRUCache {
    /// The number of values currently stored in the cache
    var count: Int {
        values.count
    }

    /// Is the cache empty?
    var isEmpty: Bool {
        values.isEmpty
    }

    /// Returns all values in the cache from oldest to newest
    var allValues: [Value] {
        lock.lock()
        defer { lock.unlock() }
        var values = [Value]()
        var next = head
        while let container = next {
            values.append(container.value)
            next = container.next
        }
        return values
    }

    /// Insert a value into the cache with optional `cost`
    func save(_ value: Value?, forKey key: Key, cost: Int = 0, ttl: TimeInterval=604800) {
        guard let value = value else {
            removeValue(forKey: key)
            return
        }
        lock.lock()
        if let container = values[key] {
            container.value = value
            totalCost -= container.cost
            container.cost = cost
            remove(container)
            append(container)
        } else {
            let container = Container(
                value: value,
                cost: cost,
                ttl: dateProvider().addingTimeInterval(ttl),
                key: key
            )
            values[key] = container
            append(container)
        }
        totalCost += cost
        lock.unlock()
        clean()
    }

    /// Remove a value  from the cache and return it
    @discardableResult func removeValue(forKey key: Key) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard let container = values.removeValue(forKey: key) else {
            return nil
        }
        remove(container)
        totalCost -= container.cost
        return container.value
    }

    /// Fetch a value from the cache
    func get(forKey key: Key) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        if let container = values[key] {
            guard dateProvider() < container.ttl else {
                // Discard values that have expired
                values.removeValue(forKey: key)
                remove(container)
                return nil
            }

            remove(container)
            append(container)
            return container.value
        }
        return nil
    }

    /// Remove all values from the cache
    func emptyCache() {
        lock.lock()
        values.removeAll()
        head = nil
        tail = nil
        lock.unlock()
    }
}

private extension LRUCache {
    final class Container {
        var value: Value
        var cost: Int
        var ttl: Date
        let key: Key
        unowned(unsafe) var prev: Container?
        unowned(unsafe) var next: Container?

        init(value: Value, cost: Int, ttl: Date, key: Key) {
            self.value = value
            self.cost = cost
            self.key = key
            self.ttl = ttl
        }
    }

    // Remove container from list (must be called inside lock)
    func remove(_ container: Container) {
        if head === container {
            head = container.next
        }
        if tail === container {
            tail = container.prev
        }
        container.next?.prev = container.prev
        container.prev?.next = container.next
        container.next = nil
    }

    // Append container to list (must be called inside lock)
    func append(_ container: Container) {
        assert(container.next == nil)
        if head == nil {
            head = container
        }
        container.prev = tail
        tail?.next = container
        tail = container
    }

    // Remove expired values (must be called outside lock)
    func clean() {
        lock.lock()
        defer { lock.unlock() }
        while totalCost > totalCostLimit || count > countLimit,
              let container = head
        {
            remove(container)
            values.removeValue(forKey: container.key)
            totalCost -= container.cost
        }
    }
}
