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
    sha256 = "f7dbce3717772fc5cb864930d18f96aa4e443b0d3dc713b13fbd45e502c55ce0",
    url = "https://github.com/bazelbuild/rules_apple/releases/download/3.17.1/rules_apple.3.17.1.tar.gz",
)

git_repository(
    name = "SwiftRuleEngine",
    remote = "https://github.com/santalvarez/swift-rule-engine.git",
    tag = "1.5.1",
)

http_archive(
    name = "rules_xcodeproj",
    sha256 = "13d4888dbc674bbd59227cbba841b901ce7b976d5f7e829a931fe5fd84f3da2b",
    url = "https://github.com/MobileNativeFoundation/rules_xcodeproj/releases/download/2.12.1/release.tar.gz",
)

http_archive(
    name = "rules_shell",
    sha256 = "bc61ef94facc78e20a645726f64756e5e285a045037c7a61f65af2941f4c25e1",
    strip_prefix = "rules_shell-0.4.1",
    url = "https://github.com/bazelbuild/rules_shell/releases/download/v0.4.1/rules_shell-v0.4.1.tar.gz",
)

http_archive(
    name = "rules_python",
    sha256 = "2cc26bbd53854ceb76dd42a834b1002cd4ba7f8df35440cf03482e045affc244",
    strip_prefix = "rules_python-1.3.0",
    url = "https://github.com/bazel-contrib/rules_python/releases/download/1.3.0/rules_python-1.3.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()


load("@rules_shell//shell:repositories.bzl", "rules_shell_dependencies", "rules_shell_toolchains")

rules_shell_dependencies()

rules_shell_toolchains()

load("@SwiftRuleEngine//:deps.bzl",
     "swift_rule_engine_dependencies")

swift_rule_engine_dependencies()


# XCODE PROJECT RULES

load(
    "@rules_xcodeproj//xcodeproj:repositories.bzl",
    "xcodeproj_rules_dependencies",
)

xcodeproj_rules_dependencies()

load("@bazel_features//:deps.bzl", "bazel_features_deps")

bazel_features_deps()

# APPLE RULES
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
