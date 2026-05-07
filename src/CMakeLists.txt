add_library(mylib
	commit/commit.h
	commit/commit.cpp
)
target_include_directories(mylib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
