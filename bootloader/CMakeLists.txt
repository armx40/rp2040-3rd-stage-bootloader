cmake_minimum_required(VERSION 3.13)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
# add_definitions(-DPICO_MBEDTLS_CONFIG_FILE="./mbedtls-config-changes.h")
include(pico_sdk_import.cmake)
include(pico_extras_import.cmake)

project(c3rl_bootloader)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()



# rest of your project
add_executable(main
src/main.c
src/debug.c
src/log.c
src/time.c
src/storage.c
src/crypto.c
src/crc32.c
)

# Add pico_stdlib library which aggregates commonly used features
target_link_libraries(
    main
    pico_stdlib
    pico_mbedtls
    hardware_rtc
 )

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(main)
