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
