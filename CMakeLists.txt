cmake_minimum_required(VERSION 3.17)
project(SUN-AGENT)
set(CMAKE_CXX_STANDARD 17)
set(PYTORCH /home/zhulin/anaconda3/envs/torch)
include_directories(
    /home/zhulin/anaconda3/envs/torch/include/python3.8
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
link_directories(
    /home/zhulin/anaconda3/envs/torch/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
)
aux_source_directory(./src SRC_LIST)
add_executable(main main.cpp ${SRC_LIST})
target_link_libraries(main elasticlient jsoncpp cpr curl python3.8)