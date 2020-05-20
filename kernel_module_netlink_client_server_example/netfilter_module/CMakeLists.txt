cmake_minimum_required(VERSION 3.0)
project(simple_kernel_module)

set ( DRV_MAJOR 1 )
set ( DRV_MINOR 0 )
set ( DRV_PATCH 0 )

set ( DRV_VERSION ${DRV_MAJOR}.${DRV_MINOR}.${DRV_PATCH} )

execute_process(COMMAND uname -r
                    OUTPUT_VARIABLE os_version
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

set( DRIVER_FILE mydriver.ko )
set( KERNEL_DIR ${CMAKE_SOURCE_DIR}/kernel-source )
set( KBUILD_CMD ${CMAKE_MAKE_PROGRAM}
                -C ${KERNEL_DIR}
                M=${CMAKE_SOURCE_DIR} modules)

add_custom_command( OUTPUT ${DRIVER_FILE}
                    COMMAND ${KBUILD_CMD}
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    DEPENDS simple_kernel_module.c Kbuild VERBATIM )

add_custom_target ( driver ALL DEPENDS ${DRIVER_FILE} )
