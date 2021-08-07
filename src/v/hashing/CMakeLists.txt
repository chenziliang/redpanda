if (NOT TP_BUILD)
    find_package(Crc32c REQUIRED)
endif()

v_cc_library(
  NAME rphashing
  SRCS murmur.cc
  COPTS
    -Wno-implicit-fallthrough
  DEPS
    Crc32c::crc32c
  DEFINES
    -DXXH_PRIVATE_API
)

add_subdirectory(tests)
