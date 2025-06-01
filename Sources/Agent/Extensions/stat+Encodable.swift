//
//  stat+Encodable.swift
//  Agent
//
//  Created by Santiago Alvarez on 01/06/2025.
//  Copyright © 2025 Santiago Alvarez. All rights reserved.
//

import Foundation
import SwiftRuleEngine

extension stat: Encodable, StringSubscriptable {

    static private let keys: [String: PartialKeyPath<Self>] = [
        "st_rdev": \.st_rdev,
        "st_atimespec": \.st_atimespec.tv_sec,
        "st_dev": \.st_dev,
        "st_birthtimespec": \.st_birthtimespec.tv_sec,
        "st_blksize": \.st_blksize,
        "st_blocks": \.st_blocks,
        "st_ctimespec": \.st_ctimespec.tv_sec,
        "st_gid": \.st_gid,
        "st_uid": \.st_uid,
        "st_ino": \.st_ino,
        "st_mode": \.st_mode,
        "st_size": \.st_size,
        "st_nlink": \.st_nlink,
        "st_mtimespec": \.st_mtimespec.tv_sec
    ]

    public subscript(key: String) -> Any? {
        guard let kp = Self.keys[key] else {
            return nil
        }
        return self[keyPath: kp]
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.st_rdev, forKey: .st_rdev)
        try container.encode(self.st_atimespec.tv_sec, forKey: .st_atimespec)
        try container.encode(self.st_dev, forKey: .st_dev)
        try container.encode(self.st_birthtimespec.tv_sec, forKey: .st_birthtimespec)
        try container.encode(self.st_blksize, forKey: .st_blksize)
        try container.encode(self.st_blocks, forKey: .st_blocks)
        try container.encode(self.st_ctimespec.tv_sec, forKey: .st_ctimespec)
        try container.encode(self.st_gid, forKey: .st_gid)
        try container.encode(self.st_uid, forKey: .st_uid)
        try container.encode(self.st_ino, forKey: .st_ino)
        try container.encode(self.st_mode, forKey: .st_mode)
        try container.encode(self.st_size, forKey: .st_size)
        try container.encode(self.st_nlink, forKey: .st_nlink)
        try container.encode(self.st_mtimespec.tv_sec, forKey: .st_mtimespec)
    }

    enum CodingKeys: String, CodingKey {
        case st_rdev, st_atimespec, st_dev, st_birthtimespec,
             st_blksize, st_blocks, st_ctimespec, st_gid, st_uid,
             st_ino, st_mode, st_size, st_nlink, st_mtimespec
    }
}


extension statfs: Encodable, StringSubscriptable {
    static private let keys: [String: PartialKeyPath<Self>] = [
        "f_bsize": \.f_bsize,
        "f_iosize": \.f_iosize,
        "f_blocks": \.f_blocks,
        "f_bfree": \.f_bfree,
        "f_bavail": \.f_bavail,
        "f_files": \.f_files,
        "f_ffree": \.f_ffree,
        "f_owner": \.f_owner,
        "f_type": \.f_type,
        "f_flags": \.f_flags,
        "f_fssubtype": \.f_fssubtype,
        "f_fstypename": \.fstypename,
        "f_mntonname": \.fmntonname,
        "f_mntfromname": \.fmntfromname
    ]

    public subscript(key: String) -> Any? {
        guard let kp = Self.keys[key] else {
            return nil
        }
        return self[keyPath: kp]
    }

    var fstypename: String {
        return withUnsafePointer(to: self.f_fstypename){ tuplePtr in
            guard let start = tuplePtr.pointer(to: \.0) else {
                return ""
            }
            return String(cString: start)
        }
    }

    var fmntonname: String {
        return withUnsafePointer(to: self.f_mntonname) { tuplePtr in
            guard let start = tuplePtr.pointer(to: \.0) else {
                return ""
            }
            return String(cString: start)
        }
    }

    var fmntfromname: String {
        return withUnsafePointer(to: self.f_mntfromname) { tuplePtr in
            guard let start = tuplePtr.pointer(to: \.0) else {
                return ""
            }
            return String(cString: start)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(f_bsize, forKey: .f_bsize)
        try container.encode(f_iosize, forKey: .f_iosize)
        try container.encode(f_blocks, forKey: .f_blocks)
        try container.encode(f_bfree, forKey: .f_bfree)
        try container.encode(f_bavail, forKey: .f_bavail)
        try container.encode(f_files, forKey: .f_files)
        try container.encode(f_ffree, forKey: .f_ffree)
        try container.encode(f_owner, forKey: .f_owner)
        try container.encode(f_type, forKey: .f_type)
        try container.encode(f_flags, forKey: .f_flags)
        try container.encode(f_fssubtype, forKey: .f_fssubtype)
        try container.encode(f_owner, forKey: .f_owner)
        try container.encode(fmntfromname, forKey: .f_mntfromname)
        try container.encode(fmntonname, forKey: .f_mntonname)
        try container.encode(fstypename, forKey: .f_fstypename)
    }


    enum CodingKeys: String, CodingKey {
        case f_bsize, f_iosize, f_blocks, f_bfree, f_bavail, f_files, f_ffree,
             f_fsid, f_owner, f_type, f_flags, f_fssubtype, f_fstypename,
             f_mntonname, f_mntfromname
    }
}
