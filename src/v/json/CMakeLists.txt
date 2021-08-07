if(NOT TP_BUILD)
  v_cc_library(
    NAME json
    SRCS
      json.cc
    DEPS
      Seastar::seastar
  )
else()
  v_cc_library(
    NAME json
    SRCS
      json.cc
    DEPS
      rapidjson_headers_only
      Seastar::seastar
  )
endif()

add_subdirectory(tests)
