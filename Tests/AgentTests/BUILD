load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")
load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")

BRIDGING_HEADER = "Tests/AgentTests/AgentTests-Bridging-Header.h"


objc_library(
    name = "agent_tests_objc_lib",
    srcs = ["EndpointSecurity/ESUtils.m"],
    hdrs = [
        "EndpointSecurity/ESUtils.h",
        "AgentTests-Bridging-Header.h"
    ],
)

swift_library(
    name = "agent_tests_lib",
    testonly = True,
    srcs = glob(["**/*.swift"]),
    copts = [
        "-import-objc-header", BRIDGING_HEADER
    ],
    deps = [
        "//Sources/Agent:agent_lib",
        ":agent_tests_objc_lib"
    ],
    visibility = ["//:wizard_package_group"],
)


macos_unit_test(
    name = "agent_tests",
    resources = glob(["Resources/**/*"]),
    size = "medium",
    deps = [
        ":agent_tests_lib",
    ],
    minimum_os_version = "13.0",
    visibility = ["//visibility:public"],
)