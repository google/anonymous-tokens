#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_STATUS_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_STATUS_UTILS_H_

#include "absl/base/optimization.h"
#include "absl/status/status.h"


namespace anonymous_tokens {

#define _ANON_TOKENS_STATUS_MACROS_CONCAT_NAME(x, y) \
  _ANON_TOKENS_STATUS_MACROS_CONCAT_IMPL(x, y)
#define _ANON_TOKENS_STATUS_MACROS_CONCAT_IMPL(x, y) x##y

#define ANON_TOKENS_ASSIGN_OR_RETURN(lhs, rexpr)                             \
  _ANON_TOKENS_ASSIGN_OR_RETURN_IMPL(                                        \
      _ANON_TOKENS_STATUS_MACROS_CONCAT_NAME(_status_or_val, __LINE__), lhs, \
      rexpr)

#define _ANON_TOKENS_ASSIGN_OR_RETURN_IMPL(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                       \
  if (ABSL_PREDICT_FALSE(!statusor.ok())) {                      \
    return statusor.status();                                    \
  }                                                              \
  lhs = std::move(statusor.value())

#define ANON_TOKENS_RETURN_IF_ERROR(expr)                  \
  do {                                                     \
    auto _status = (expr);                                 \
    if (ABSL_PREDICT_FALSE(!_status.ok())) return _status; \
  } while (0)

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_STATUS_UTILS_H_
