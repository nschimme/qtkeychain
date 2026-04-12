cmake_minimum_required(VERSION 3.16)
project(wasm_example)

find_package(Qt6 COMPONENTS Core REQUIRED)
find_package(Qt6Keychain REQUIRED)

add_executable(wasm_example main.cpp)
target_link_libraries(wasm_example Qt6::Core Qt6Keychain::Qt6Keychain)
