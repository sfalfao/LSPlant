cmake_minimum_required(VERSION 3.18.1)
project(lsparself)

set(CMAKE_CXX_STANDARD 23)

add_library(lsparself STATIC lsparself.cpp)
target_include_directories(lsparself PUBLIC include)
target_link_libraries(lsparself PUBLIC log)
