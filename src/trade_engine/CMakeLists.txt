# Define the library for utils
add_executable(trade_engine
	trade_engine.cpp
)

target_link_libraries(trade_engine libengine)