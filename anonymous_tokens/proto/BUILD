load("@com_google_protobuf//bazel:java_lite_proto_library.bzl", "java_lite_proto_library")
load("@com_google_protobuf//bazel:java_proto_library.bzl", "java_proto_library")
load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")
load("@com_google_protobuf//build_defs:kt_jvm_proto_library.bzl", "kt_jvm_proto_library")

# Public protos for Anonymous Tokens service.
load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//:__subpackages__"])

proto_library(
    name = "anonymous_tokens_proto",
    srcs = ["anonymous_tokens.proto"],
)

cc_proto_library(
    name = "anonymous_tokens_cc_proto",
    deps = [":anonymous_tokens_proto"],
)

java_proto_library(
    name = "anonymous_tokens_java_proto",
    deps = [":anonymous_tokens_proto"],
)

kt_jvm_proto_library(
    name = "anonymous_tokens_kt_proto",
    visibility = [
        "//java/com/google/communication/rcs/abuse/protection/appletoken/service:__subpackages__",
        "//javatests/com/google/communication/rcs/abuse/protection/appletoken/service:__subpackages__",
    ],
    deps = [":anonymous_tokens_proto"],
)

java_lite_proto_library(
    name = "anonymous_tokens_java_proto_lite",
    deps = [":anonymous_tokens_proto"],
)
