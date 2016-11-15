cmake_minimum_required(VERSION 2.8)

PROJECT(scal C)
ADD_DEFINITIONS(-O2 -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)
ADD_DEFINITIONS(-I${CMAKE_SOURCE_DIR})

IF(APPLE)
	SET(CMAKE_SHARED_MODULE_CREATE_C_FLAGS "${CMAKE_SHARED_MODULE_CREATE_C_FLAGS} -undefined dynamic_lookup")
ENDIF(APPLE)

FIND_PATH(ubus_include_dir libubus.h)
INCLUDE_DIRECTORIES(${ubus_include_dir})

FIND_LIBRARY(ubox_library NAMES ubox)
FIND_LIBRARY(ubus_library NAMES ubus)

ADD_EXECUTABLE(scald scald.c ubus.c plugin.c model.c)
TARGET_LINK_LIBRARIES(scald ubus ${ubox_library} ${ubus_library} dl)
