load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# OpenSSL
http_archive(
    name = "openssl",
    url = "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1n.tar.gz",
    sha256 = "6b2d2440ced8c802aaa61475919f0870ec556694c466ebea460e35ea2b14839e",
    strip_prefix = "openssl-OpenSSL_1_1_1n",
    build_file = "//tools:openssl.BUILD",
)

# Yara
http_archive(
    name = "yara",
    url = "https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz",
    sha256 = "a9587a813dc00ac8cdcfd6646d7f1c172f730cda8046ce849dfea7d3f6600b15",
    strip_prefix = "yara-4.3.2",
    build_file = "//tools:yara.BUILD",
)

http_archive(
    name = "build_bazel_rules_apple",
    sha256 = "34c41bfb59cdaea29ac2df5a2fa79e5add609c71bb303b2ebb10985f93fa20e7",
    url = "https://github.com/bazelbuild/rules_apple/releases/download/3.1.1/rules_apple.3.1.1.tar.gz",
)

git_repository(
    name = "SwiftRuleEngine",
    remote = "https://github.com/santalvarez/swift-rule-engine.git",
    tag = "1.5.0",
)

http_archive(
    name = "rules_xcodeproj",
    sha256 = "f5c1f4bea9f00732ef9d54d333d9819d574de7020dbd9d081074232b93c10b2c",
    url = "https://github.com/MobileNativeFoundation/rules_xcodeproj/releases/download/1.13.0/release.tar.gz",
)

load("@SwiftRuleEngine//:deps.bzl",
     "swift_rule_engine_dependencies")

swift_rule_engine_dependencies()

load(
    "@build_bazel_rules_apple//apple:repositories.bzl",
    "apple_rules_dependencies",
)

apple_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:repositories.bzl",
    "swift_rules_dependencies",
)

swift_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:extras.bzl",
    "swift_rules_extra_dependencies",
)

swift_rules_extra_dependencies()

load(
    "@build_bazel_apple_support//lib:repositories.bzl",
    "apple_support_dependencies",
)

apple_support_dependencies()

load(
    "@rules_xcodeproj//xcodeproj:repositories.bzl",
    "xcodeproj_rules_dependencies",
)

xcodeproj_rules_dependencies()

load("@bazel_features//:deps.bzl", "bazel_features_deps")

bazel_features_deps()
