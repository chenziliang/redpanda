include(diagnostic_colors)

# HACK rapidjson

add_library (rapidjson_headers_only INTERFACE)
target_include_directories (rapidjson_headers_only SYSTEM BEFORE INTERFACE ${RAPIDJSON_INCLUDE_DIR})

add_compile_definitions(TP_BUILD)

# from seastar/CMakeLists.txt. unfortunately this snippet doesn't appear to be
# installed along with the rest of seastar.
function (seastar_generate_swagger)
  set (one_value_args TARGET VAR IN_FILE OUT_FILE)
  cmake_parse_arguments (args "" "${one_value_args}" "" ${ARGN})
  get_filename_component (out_dir ${args_OUT_FILE} DIRECTORY)

  find_program(GENERATOR "seastar-json2code.py")
  set (generator "${GENERATOR}")

  add_custom_command (
    DEPENDS
      ${args_IN_FILE}
      ${generator}
    OUTPUT ${args_OUT_FILE}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${out_dir}
    COMMAND ${generator} -f ${args_IN_FILE} -o ${args_OUT_FILE})

  add_custom_target (${args_TARGET}
    DEPENDS ${args_OUT_FILE})

  set (${args_VAR} ${args_OUT_FILE} PARENT_SCOPE)
endfunction ()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

if((EXISTS "${PROJECT_BINARY_DIR}/bin/kafka-python-env") AND (EXISTS "${PROJECT_BINARY_DIR}/bin/kafka-codegen-venv"))
  message(STATUS "Kafka protocol generators are already created")
else()
  execute_process(
    COMMAND python3 -m venv env
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  execute_process(
    COMMAND env/bin/pip install pex
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  execute_process(
    COMMAND env/bin/pex jsonschema jinja2 -o ${PROJECT_BINARY_DIR}/bin/kafka-codegen-venv
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  execute_process(
    COMMAND env/bin/pex kafka-python -o ${PROJECT_BINARY_DIR}/bin/kafka-python-env
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

# Alias libraries to minimize the cmake file changes
add_library(Base64::base64 ALIAS base64_ext)
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
