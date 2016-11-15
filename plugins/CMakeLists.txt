cmake_minimum_required(VERSION 2.8)
PROJECT(scald_plugins C)

IF(APPLE)
	SET(CMAKE_SHARED_MODULE_CREATE_C_FLAGS "${CMAKE_SHARED_MODULE_CREATE_C_FLAGS} -undefined dynamic_lookup")
ENDIF(APPLE)

ADD_LIBRARY(example MODULE example.c)
SET_TARGET_PROPERTIES(example PROPERTIES
	OUTPUT_NAME scapi_example
	PREFIX ""
)

ADD_LIBRARY(json MODULE json/plugin.c json/parser.c)
SET_TARGET_PROPERTIES(json PROPERTIES
	OUTPUT_NAME scapi_json
	PREFIX ""
)

FIND_PATH(json_include_dir .h)

INCLUDE(FindPkgConfig)
PKG_SEARCH_MODULE(JSONC json-c)
IF(JSONC_FOUND)
  INCLUDE_DIRECTORIES(${JSONC_INCLUDE_DIRS})
ENDIF()

INCLUDE_DIRECTORIES(${ubus_include_dir})

FIND_LIBRARY(json_library NAMES json-c)
FIND_LIBRARY(blobmsg_json_library NAMES blobmsg_json)
FIND_LIBRARY(ubus_library NAMES ubus)
FIND_LIBRARY(json_script_library NAMES json_script)

TARGET_LINK_LIBRARIES(json ${json_library} ${blobmsg_json_library} ${ubus_library} ${json_script_library})
