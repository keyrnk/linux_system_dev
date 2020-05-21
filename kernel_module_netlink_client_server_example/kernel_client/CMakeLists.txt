cmake_minimum_required(VERSION 3.0)

project(kernel_module_client)

set(SOURCES kernel_module_client.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})
