if (NOT TP_BUILD)
  v_cc_library(
    NAME security
    SRCS
      scram_algorithm.cc
      scram_credential.cc
      scram_authenticator.cc
      acl_store.cc
    DEPS
      v::bytes
      absl::flat_hash_map
      absl::flat_hash_set
  )
else()
  v_cc_library(
    NAME security
    SRCS
      scram_algorithm.cc
      scram_credential.cc
      scram_authenticator.cc
      acl_store.cc
    DEPS
      v::bytes
      absl::flat_hash_map
      absl::flat_hash_set
      ssl
  )
endif()

add_subdirectory(tests)
