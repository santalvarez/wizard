//
//  LRUCachePerformanceTests.swift
//  AgentTests
//
//  Created by Santiago Alvarez on 02/06/2023.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import XCTest
@testable import Agent

class LRUCachePerformanceTests: XCTestCase {
    let iterations = 40000

    func testInsertionPerformance() {
        measure {
            let cache = LRUCache<Int, Int>()
            for i in 0 ..< iterations {
                cache.save(i, forKey: i)
            }
        }
    }

    func testLookupPerformance() {
        let cache = LRUCache<Int, Int>()
        for i in 0 ..< iterations {
            cache.save(i, forKey: i)
        }
        measure {
            for i in 0 ..< iterations {
                _ = cache.get(forKey: i)
            }
        }
    }

    func testRemovalPerformance() {
        let cache = LRUCache<Int, Int>()
        for i in 0 ..< iterations {
            cache.save(i, forKey: i)
        }
        measure {
            for i in 0 ..< iterations {
                _ = cache.removeValue(forKey: i)
            }
        }
    }

    func testOverflowInsertionPerformance() {
        measure {
            let cache = LRUCache<Int, Int>(countLimit: 10000)
            for i in 0 ..< iterations {
                cache.save(i, forKey: i)
            }
        }
    }
}
