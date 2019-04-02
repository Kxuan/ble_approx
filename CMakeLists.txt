cmake_minimum_required(VERSION 3.0)
project(ble_approx C)

set(CMAKE_C_STANDARD 99)
include(FindPkgConfig)
pkg_check_modules(BLUEZ REQUIRED bluez>=5)

link_directories(${BLUEZ_LIBRARY_DIRS})
include_directories(${BLUEZ_INCLUDE_DIRS})
add_compile_options(${BLUEZ_CFLAGS})
add_link_options(${BLUEZ_LDFLAGS})
link_libraries(${BLUEZ_LIBRARIES})

add_executable(ble_approx ble_main.c)
install(TARGETS ble_approx RUNTIME DESTINATION bin)