find_package(Protobuf REQUIRED)

add_library(mylib
	commit/my_commit.h
	commit/my_commit.cpp
	bpfmanage.cpp
	bpfmanage.h
	message/message.pb.h
	message/message.pb.cc
	message/tcpclient.h
	message/tcpclient.cpp
)

target_include_directories(mylib
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}
	${SPDLOG_ROOT}/include
	protobuf::libprotobuf
)
