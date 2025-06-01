package(
    default_visibility = ["//visibility:public"],
)

config_setting(
    name = "darwin64",
    values = {"cpu": "darwin_x86_64"},
)

config_setting(
    name = "darwinarm64",
    values = {"cpu": "darwin_arm64"},
)

genrule(
    name = "openssl-build",
    srcs = glob(
        ["**/*"],
        exclude = ["bazel-*"],
    ),
    outs = [
        "libcrypto.a",
        "libssl.a",
        "include/openssl/opensslconf.h",
    ],
    cmd = """
        CONFIG_LOG=$$(mktemp)
        MAKE_LOG=$$(mktemp)
        OPENSSL_ROOT=$$(dirname $(location config))
        DARWIN_TYPE="""+ select({":darwin64": "darwin64-x86_64-cc", ":darwinarm64": "darwin64-arm64-cc"}) +"""
        pushd $$OPENSSL_ROOT > /dev/null
            if ! ./Configure $$DARWIN_TYPE > $$CONFIG_LOG; then
                cat $$CONFIG_LOG
            fi
            if ! make -s -j 4 > $$MAKE_LOG; then
                cat $$MAKE_LOG
            fi
        popd > /dev/null
        cp $$OPENSSL_ROOT/libcrypto.a $(location libcrypto.a)
        cp $$OPENSSL_ROOT/libssl.a $(location libssl.a)
        cp $$OPENSSL_ROOT/include/openssl/opensslconf.h $(location include/openssl/opensslconf.h)
    """
)

cc_library(
    name = "libcrypto",
    srcs = ["libcrypto.a"],
    hdrs = glob(["include/openssl/*.h"]) + ["include/openssl/opensslconf.h"],
    includes = ["include"],
    deps = [":openssl-build"],
    visibility = ["//visibility:public"],
)
