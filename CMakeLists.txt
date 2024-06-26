cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

cmake_policy (SET CMP0054 NEW)

include (ExternalProject)
set (CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

option (USING_ENTITY_MANAGER_DECORATORS
        "Enable using EM decorators to map FRUs to entity IDs" ON)

option (USE_ETH1_NETWORK_DEVICE
        "Use 'eth1' network device for ntp and dns settings,
         instead of using default 'eth0' device"
        OFF)

option (sbmr-boot-progress
        "To Support Boot Progreess codes for ARM systems"
	OFF)

option (GH-oem-commands
        "To support GH specific ipmi-oem-commands"
        OFF)


option (BF3-OEM-COMMANDS
        "To support disable specific ipmi-oem-commands"
        OFF)

option (disable-smbpbi-passthru
        "To disable SMBPBI passthru commands"
        OFF)

#[[Optional support for Global Write-Protect FRU Edit Protection]]

if(WP-GPIO AND WP-GPIO-CHIP)
	
	add_compile_definitions(WP_GPIO=${WP-GPIO})
	add_compile_definitions(CHIP=${WP-GPIO-CHIP})
	
endif()

option (custom-pwm-fan
        "To support customize platforms pwm/fan configurations"
        OFF)

option (custom-oem-cmd
        "To support commands/configuration relevant for new platforms"
        OFF)
option (bf3-chassis-commands
        "To support commands relevant only to BF3"
        OFF)


set (
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wtype-limits \
    -Wnull-dereference \
"
)

project (nvidia-ipmi-oem CXX)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)
add_definitions (-DBOOST_ASIO_DISABLE_THREADS)
add_definitions (-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_definitions (-Wno-psabi)

find_package (PkgConfig REQUIRED)
pkg_check_modules (LOGGING phosphor-logging REQUIRED)
include_directories (SYSTEM ${LOGGING_INCLUDE_DIRS})
link_directories (${LOGGING_LIBRARY_DIRS})

pkg_check_modules (LIBIPMID libipmid REQUIRED)
include_directories (SYSTEM ${LIBIPMID_INCLUDE_DIRS})
link_directories (${LIBIPMID_LIBRARY_DIRS})

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package (OpenSSL REQUIRED)
include_directories (SYSTEM ${OPENSSL_INCLUDE_DIR})

include_directories (SYSTEM ${CMAKE_BINARY_DIR})
add_custom_command(OUTPUT include/ipmi-whitelist.hpp
                  COMMAND ./generate-whitelist.py
                  ARGS ipmi-whitelist.conf ${CMAKE_BINARY_DIR}/ipmi-whitelist.hpp
                  MAIN_DEPENDENCY ipmi-whitelist.conf
                  DEPENDS generate-whitelist.py
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


# common libraries
SET(common_library_sources
    src/storagecommands.cpp src/sensorcommands.cpp
)

# flag driven libraries
if(GH-oem-commands)
    include_directories (${CMAKE_CURRENT_SOURCE_DIR}/Grace/include)
    SET(flag_library_sources
        Grace/src/ghoemcommands.cpp Grace/src/sbmr-bootprogress.cpp
    )
else()
    if(SPECTRE-OEM-COMMANDS)
    SET (flag_library_sources
                src/oemcommands.cpp src/sbmr-bootprogress.cpp
                src/BF/oemcommands.cpp src/BF/spectre/oemcommands.cpp
		src/BF/chassiscommands.cpp
    )
    elseif(BF2-OEM-COMMANDS)
    SET (flag_library_sources
                src/oemcommands.cpp src/sbmr-bootprogress.cpp
                src/BF/oemcommands.cpp src/BF/BF2/oemcommands.cpp
		src/BF/chassiscommands.cpp
    )
    elseif(BF3-OEM-COMMANDS)
    SET(flag_library_sources
                src/oemcommands.cpp src/sbmr-bootprogress.cpp
                src/BF/oemcommands.cpp src/BF/chassiscommands.cpp
        )
    else()
    SET(flag_library_sources
            src/oemcommands.cpp src/sbmr-bootprogress.cpp
        )

    endif()

endif()

if(disable-smbpbi-passthru)
    add_definitions (-DENABLE_SMBPBI_PASSTHRU=0)
else()
    add_definitions (-DENABLE_SMBPBI_PASSTHRU=1)
endif()

if(custom-pwm-fan)
    add_compile_definitions(CUSTOM_PWM_FAN=${custom-pwm-fan})
    add_compile_definitions(CONFIG_PWM=${config-pwm})
    add_compile_definitions(CONFIG_FAN_ZONE_CTRL_NAME1=${config-fanZoneCtrlName1})
    add_compile_definitions(CONFIG_FAN_ZONE_CTRL_NAME2=${config-fanZoneCtrlName2})
endif()

if(custom-oem-cmd)
	add_compile_definitions(CUSTOM_OEM_CMD=${custom-oem-cmd})
endif()

if(BF2-OEM-COMMANDS OR BF3-OEM-COMMANDS OR SPECTRE-OEM-COMMANDS)
    add_library ( znvipmioemcmds SHARED ${flag_library_sources})
else()
    add_library ( znvipmioemcmds SHARED ${common_library_sources} ${flag_library_sources})
endif()

if(bf3-chassis-commands)
    add_definitions (-DBF3_CHASSIS_COMMAND)
endif()

set_target_properties (znvipmioemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (znvipmioemcmds PROPERTIES SOVERSION "0")
target_link_libraries (znvipmioemcmds stdc++fs)
target_link_libraries (znvipmioemcmds ipmid)
target_link_libraries (znvipmioemcmds sdbusplus)
target_link_libraries (znvipmioemcmds phosphor_logging)
target_link_libraries (znvipmioemcmds -luserlayer)
target_link_libraries (znvipmioemcmds -lchannellayer)
target_link_libraries (znvipmioemcmds ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries (znvipmioemcmds gpiodcxx)
target_link_libraries (znvipmioemcmds pam)

install (TARGETS znvipmioemcmds DESTINATION lib/ipmid-providers)

target_compile_definitions (
    znvipmioemcmds PRIVATE
    $<$<BOOL:${USING_ENTITY_MANAGER_DECORATORS}>:
    -DUSING_ENTITY_MANAGER_DECORATORS>
)

target_compile_definitions (
    znvipmioemcmds PRIVATE
    $<$<BOOL:${USE_ETH1_NETWORK_DEVICE}>:
    -DUSE_ETH1_NETWORK_DEVICE>
)

target_compile_definitions (
    znvipmioemcmds PRIVATE
    $<$<BOOL:${USING_OEM_SENSOR}>:
    -DUSING_OEM_SENSOR>
)

target_compile_definitions (
    znvipmioemcmds PRIVATE
    $<$<BOOL:${sbmr-boot-progress}>:
    -DFEATURE_SBMR_BOOTPROGRESS>
)
