//
//  LRUCacheTests.swift
//  AgentTests
//
//  Created by Santiago Alvarez on 02/06/2023.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import XCTest
@testable import Agent

class LRUCacheTests: XCTestCase {
    func testCountLimit() {
        let cache = LRUCache<Int, Int>(countLimit: 2)
        cache.save(0, forKey: 0)
        XCTAssertNotNil(cache.get(forKey: 0))
        cache.save(1, forKey: 1)
        cache.save(2, forKey: 2)
        XCTAssertNil(cache.get(forKey: 0))
        XCTAssertNotNil(cache.get(forKey: 1))
        XCTAssertNotNil(cache.get(forKey: 2))
        XCTAssertEqual(cache.count, 2)
    }

    func testCostLimit() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 3)
        cache.save(0, forKey: 0, cost: 1)
        cache.save(1, forKey: 1, cost: 1)
        XCTAssertEqual(cache.count, 2)
        XCTAssertEqual(cache.totalCost, 2)
        cache.save(2, forKey: 2, cost: 2)
        XCTAssertNil(cache.get(forKey: 0))
        XCTAssertNotNil(cache.get(forKey: 1))
        XCTAssertNotNil(cache.get(forKey: 2))
        XCTAssertEqual(cache.count, 2)
        XCTAssertEqual(cache.totalCost, 3)
    }

    func testAdjustCountLimit() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 2)
        cache.save(0, forKey: 0, cost: 1)
        cache.save(1, forKey: 1, cost: 1)
        cache.countLimit = 1
        XCTAssertNil(cache.get(forKey: 0))
        XCTAssertEqual(cache.count, 1)
    }

    func testAdjustCostLimit() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 3)
        cache.save(0, forKey: 0, cost: 1)
        cache.save(1, forKey: 1, cost: 1)
        cache.save(2, forKey: 2, cost: 1)
        cache.totalCostLimit = 2
        XCTAssertNil(cache.get(forKey: 0))
        XCTAssertEqual(cache.count, 2)
        cache.totalCostLimit = 0
        XCTAssert(cache.isEmpty)
    }

    func testRemoveValue() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 2)
        cache.save(0, forKey: 0)
        cache.save(1, forKey: 1)
        XCTAssertEqual(cache.removeValue(forKey: 0), 0)
        XCTAssertEqual(cache.count, 1)
        XCTAssertNil(cache.removeValue(forKey: 0))
        cache.save(nil, forKey: 1)
        XCTAssert(cache.isEmpty)
    }

    func testRemoveAllValues() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 2)
        cache.save(0, forKey: 0)
        cache.save(1, forKey: 1)
        cache.emptyCache()
        XCTAssert(cache.isEmpty)
        cache.save(0, forKey: 0)
        XCTAssertEqual(cache.count, 1)
    }

    func testAllValues() {
        let cache = LRUCache<Int, Int>(totalCostLimit: 2)
        cache.save(0, forKey: 0)
        cache.save(1, forKey: 1)
        XCTAssertEqual(cache.allValues, [0, 1])
        cache.save(0, forKey: 0)
        XCTAssertEqual(cache.allValues, [1, 0])
        cache.emptyCache()
        XCTAssert(cache.allValues.isEmpty)
    }

    func testReplaceValue() {
        let cache = LRUCache<Int, Int>()
        cache.save(0, forKey: 0, cost: 5)
        XCTAssertEqual(cache.get(forKey: 0), 0)
        XCTAssertEqual(cache.totalCost, 5)
        cache.save(1, forKey: 0, cost: 3)
        XCTAssertEqual(cache.get(forKey: 0), 1)
        XCTAssertEqual(cache.totalCost, 3)
        cache.save(2, forKey: 0, cost: 7)
        XCTAssertEqual(cache.get(forKey: 0), 2)
        XCTAssertEqual(cache.totalCost, 7)
    }

    func testMemoryWarning() {
        let cache = LRUCache<Int, Int>()
        for i in 0 ..< 100 {
            cache.save(i, forKey: i)
        }
        XCTAssertEqual(cache.count, 100)
        NotificationCenter.default.post(
            name: LRUCacheMemoryWarningNotification,
            object: nil
        )
        XCTAssert(cache.isEmpty)
    }

    func testNotificationObserverIsRemoved() {
        final class TestNotificationCenter: NotificationCenter {
            private(set) var observersCount = 0

            override func addObserver(
                forName name: NSNotification.Name?,
                object obj: Any?,
                queue: OperationQueue?,
                using block: @escaping (Notification) -> Void
            ) -> NSObjectProtocol {
                defer { observersCount += 1 }
                return super.addObserver(
                    forName: name,
                    object: obj,
                    queue: queue,
                    using: block
                )
            }

            override func removeObserver(_ observer: Any) {
                super.removeObserver(observer)
                observersCount -= 1
            }
        }

        let notificationCenter = TestNotificationCenter()
        var cache: LRUCache<Int, Int>? =
            .init(notificationCenter: notificationCenter)
        weak var weakCache = cache
        XCTAssertEqual(1, notificationCenter.observersCount)
        cache = nil
        XCTAssertNil(weakCache)
        XCTAssertEqual(0, notificationCenter.observersCount)
    }

    func testNoStackOverflowForlargeCache() {
        let cache = LRUCache<Int, Int>()
        for i in 0 ..< 100000 {
            cache.save(i, forKey: i)
        }
    }

    func testValueExpiration() {
        let mockedDateProvider: (() -> Date) = { Date() } // Default dateProvider returns the current date
        let cache = LRUCache<Int, String>(dateProvider: mockedDateProvider)

        // Add values to the cache with specific keys and cost
        for i in 1..<100 {
            cache.save("Value 1", forKey: i, ttl: -10)
        }

        for i in 1..<100 {
            let value1 = cache.get(forKey: i)
            XCTAssertNil(value1, "Value 1 should have expired and be nil")
        }
    }
}
