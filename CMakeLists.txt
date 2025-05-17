cmake_minimum_required(VERSION 3.12)
project(ECDSAKeygen)


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(ecdsa_keygen MODULE ecdsa_keygen.cpp)
target_link_libraries(ecdsa_keygen PRIVATE pybind11::module OpenSSL::Crypto)
