add_executable(aegis_tests
  test_main.cc
  unit/test_browsing_data.cc
  unit/test_downloads.cc
  unit/test_engine_switches.cc
  unit/test_filter_engine.cc
  unit/test_filter_parser.cc
  unit/test_json.cc
  unit/test_network_policy.cc
  unit/test_pages_omnibox.cc
  unit/test_permissions.cc
  unit/test_policy.cc
  unit/test_psl.cc
  unit/test_settings.cc
  unit/test_updates.cc
  unit/test_url_idna.cc
  integration/test_request_pipeline.cc
  integration/test_persistence.cc
  security/test_robustness.cc
  security/test_concurrency.cc)
target_include_directories(aegis_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(aegis_tests PRIVATE aegis_core)
target_compile_definitions(aegis_tests PRIVATE AEGIS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
aegis_apply_hardening(aegis_tests)
aegis_apply_warnings(aegis_tests)
find_package(Threads REQUIRED)
target_link_libraries(aegis_tests PRIVATE Threads::Threads)

add_test(NAME aegis_tests COMMAND aegis_tests --junit=${CMAKE_BINARY_DIR}/aegis-tests.xml)
