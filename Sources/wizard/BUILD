load("@build_bazel_rules_apple//apple:macos.bzl", "macos_application")
load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")
load(
    "@rules_xcodeproj//xcodeproj:defs.bzl",
    "top_level_target",
    "xcodeproj",
)

package(
    default_visibility = ["//:wizard_package_group"],
)


swift_library(
    name = "wizard_lib",
    srcs = glob(["*.swift"]) + ["//Sources/Agent:agent_shared_files"],
    data = [
        "Base.lproj/Main.storyboard"
    ],
    visibility = ["//:wizard_package_group"],
)


macos_application(
    name = "wizard",
    additional_contents = {
        "//Sources/Agent:com.santalvarez.wizard.Agent": "Library/SystemExtensions",
    },
    app_icons = glob(["Assets.xcassets/**"]),
    bundle_id = "com.santalvarez.wizard",
    bundle_name = "Wizard",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = select({
        "//:dev_build": "wizard.entitlements",
        "//conditions:default": None,
    }),
    infoplists = ["Info.plist"],
    minimum_os_version = "13.0",
    provisioning_profile = select({
        "//:dev_build": None,
        "//conditions:default": "//provision:wizard_profile",
    }),
    version = "//:wizard_version",
    visibility = ["//visibility:public"],
    deps = [":wizard_lib"],
)

xcodeproj(
    name = "xcodeproj",
    project_name = "wizard",
    install_directory="",
    top_level_targets = [
        top_level_target(
            "//Sources/wizard:wizard",
            target_environments = ["device"]
        ),
        top_level_target(
            "//Sources/Agent:com.santalvarez.wizard.Agent",
            target_environments = ["device"]
        ),
        "//Tests/AgentTests:agent_tests"
    ],
)