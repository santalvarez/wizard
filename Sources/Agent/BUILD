load("@build_bazel_rules_apple//apple:macos.bzl", "macos_bundle")
load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")
load("//tools:expand_template.bzl", "expand_template")

package(
    default_visibility = ["//:wizard_package_group"],
)

BRIDGING_HEADER = "Sources/Agent/Agent-Bridging-Header.h"

expand_template(
    name = "expand_agent_info_plist",
    template = "Info.plist.tmpl",
    substitutions = {
        "$(PRODUCT_MODULE_NAME)": "com_santalvarez_wizard_Agent",
    },
    out = "Info.plist",
)

filegroup(
    name = "agent_shared_files",
    srcs = ["WZConstants.swift", "WZXPCService/WZXPCProtocol.swift"],
    visibility = ["//:wizard_package_group"],
)

objc_library(
    name = "agent_objc_lib",
    hdrs = ["Agent-Bridging-Header.h"],
    sdk_dylibs = ["bsm", "EndpointSecurity", "resolv", "xar"],
    visibility = ["//:wizard_package_group"],
)

swift_library(
    name = "agent_lib",
    module_name = "Agent",
    srcs = glob(["**/*.swift"]),
    visibility = ["//:wizard_package_group"],
    copts = [
        "-disable-bridging-pch",  # This fixes a weird "implicit import of bridging header" error
        "-import-objc-header", BRIDGING_HEADER
    ],
    deps = [
        "@yara//:libyara",
        "@SwiftRuleEngine//:SwiftRuleEngine",
        ":agent_objc_lib",
    ],
)

macos_bundle(
    name = "com.santalvarez.wizard.Agent",
    bundle_extension = "systemextension",
    bundle_id = "com.santalvarez.wizard.Agent",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    linkopts = ["-execute"],
    entitlements = select({
        "//:dev_build": "Agent.entitlements",
        "//conditions:default": None,
    }),
    infoplists = ["Info.plist"],
    minimum_os_version = "13.0",
    provisioning_profile = select({
        "//:dev_build": None,
        "//conditions:default": "//provision:agent_profile",
    }),
    version = "//:wizard_version",
    visibility = ["//visibility:public"],
    deps = [":agent_lib"],
)
