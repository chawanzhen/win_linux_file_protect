add_library(mylib
	commit/commit.h
	commit/commit.cpp
	kernel/kernel.c
	bpfmanage.cpp
	bpfmanage.h
)
target_include_directories(mylib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
