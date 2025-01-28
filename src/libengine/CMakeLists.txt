SET(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/Connection.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/Engine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/OrderBookProcessor.cpp
)

SET(HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/libengine/Connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/libengine/Engine.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/libengine/OrderBookProcessor.h
)

add_library(libengine
	${SOURCES} 
	${HEADERS}
)
set_target_properties(libengine PROPERTIES LINKER_LANGUAGE CXX)