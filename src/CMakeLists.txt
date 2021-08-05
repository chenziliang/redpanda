if (NOT TP_BUILD)
    find_package(Seastar REQUIRED)
    find_package(Boost REQUIRED)
    find_package(absl REQUIRED)
else()
    message(STATUS "TP BUILD...")
endif()

add_subdirectory(v)
