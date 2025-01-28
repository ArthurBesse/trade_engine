SET(HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/basic_functionality_tests.h
  ${CMAKE_CURRENT_SOURCE_DIR}/invalid_api_usage_tests.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cuncurrent_tests.h
)

SET(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/tests.cpp
)

add_executable(tests 
	${SOURCES} 
	${HEADERS}
)

target_link_libraries(tests PRIVATE libengine gtest gtest_main)

add_test(NAME ExampleTest COMMAND example_test)