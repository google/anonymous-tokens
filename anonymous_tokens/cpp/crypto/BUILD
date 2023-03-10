package(default_visibility = ["//:__subpackages__"])

licenses(["notice"])

cc_library(
    name = "blinder",
    hdrs = ["blinder.h"],
    deps = [
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "constants",
    hdrs = [
        "constants.h",
    ],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "crypto_utils",
    srcs = [
        "crypto_utils.cc",
    ],
    hdrs = [
        "crypto_utils.h",
    ],
    deps = [
        ":constants",
        ":status_utils",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "proto_utils",
    srcs = ["proto_utils.cc"],
    hdrs = ["proto_utils.h"],
    deps = [
        "//anonymous_tokens/proto:anonymous_tokens_cc_proto",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "public_metadata_crypto_utils",
    srcs = [
        "public_metadata_crypto_utils.cc",
    ],
    hdrs = [
        "public_metadata_crypto_utils.h",
    ],
    deps = [
        ":constants",
        ":crypto_utils",
        ":status_utils",
        "//anonymous_tokens/proto:anonymous_tokens_cc_proto",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "rsa_blinder",
    srcs = ["rsa_blinder.cc"],
    hdrs = ["rsa_blinder.h"],
    deps = [
        ":blinder",
        ":constants",
        ":crypto_utils",
        ":public_metadata_crypto_utils",
        ":status_utils",
        "//anonymous_tokens/proto:anonymous_tokens_cc_proto",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "status_utils",
    hdrs = ["status_utils.h"],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "utils",
    srcs = [
        "utils.cc",
    ],
    hdrs = [
        "utils.h",
    ],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)
