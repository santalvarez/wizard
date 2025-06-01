load("@build_bazel_rules_apple//apple:versioning.bzl", "apple_bundle_version")

package(default_visibility = ["//:wizard_package_group"])


licenses(["notice"])

exports_files(["LICENSE"])


apple_bundle_version(
    name = "wizard_version",
    build_version = "1.0.0",
)

package_group(
    name = "wizard_package_group",
    packages = ["//..."],
)

config_setting(
    name = "release_build",
    values = {"define": "WIZARD_BUILD=release"},
    visibility = [":wizard_package_group"],
)

# CI & dev builds
config_setting(
    name = "dev_build",
    values = {"define": "WIZARD_BUILD=dev"},
    visibility = [":wizard_package_group"],
)

test_suite(
    name = "tests",
    tests = [
        "//Tests/AgentTests:agent_tests"
    ],
)