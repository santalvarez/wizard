load("@yara//:bazel/yara.bzl", "yara_library")

licenses(["notice"])

package(
    default_visibility = ["//visibility:public"],
)

yara_library(
    name = "libyara",
    crypto_libs = ["@openssl//:libcrypto"],
    modules = [
        "hash",
        "macho",
        "tests",
        "string",
    ],
    modules_srcs = [
        "libyara/modules/math/math.c",
        "libyara/modules/pe/pe.c",
        "libyara/modules/pe/pe_utils.c",
        "libyara/modules/time/time.c",
        "libyara/modules/elf/elf.c",
        "libyara/modules/console/console.c",
        "libyara/modules/hash/hash.c",
        "libyara/modules/macho/macho.c",
        "libyara/modules/tests/tests.c",
        "libyara/modules/string/string.c",
    ],
)