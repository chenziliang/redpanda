include(diagnostic_colors)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(TP_BUILD ON)

# Alias libraries to minimize the cmake file changes
add_library(Base64::base64 ALIAS base64)
add_library(LZ4::LZ4 ALIAS lz4)
add_library(Snappy::snappy ALIAS snappy)
add_library(ZLIB::ZLIB ALIAS zlib)
add_library(Roaring::roaring ALIAS roaring)
add_library(Zstd::zstd ALIAS zstd)
add_library(Boost::unit_test_framework ALIAS _boost_test)
add_library(Crc32c::crc32c ALIAS crc32c)

if (SPLIT_SHARED_LIBRARIES)
  add_library(Hdrhistogram::hdr_histogram ALIAS hdr_histogram)
else()
  add_library(Hdrhistogram::hdr_histogram ALIAS hdr_histogram_static)
endif()

# add code
include(testing)
include(set_option)
include(v_library)
add_subdirectory(src)
