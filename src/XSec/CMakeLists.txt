cmake_minimum_required(VERSION 3.20)
get_filename_component(CURRENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)

project(${CURRENT_DIR})
cpp_execute(${PROJECT_NAME})

if(MSVC)
    #设为启动项

	# 强制设置 MyExecutable 为默认目标并缓存它
	# set(CMAKE_DEFAULT_TARGET ${PROJECT_NAME} CACHE STRING "Default target to run")

    # set_property(DIRECTORY ${CMAKE_BINARY_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME}) 
	# set_property(DIRECTORY ${CMAKE_BINARY_DIR} PROPERTY CMAKE_DEFAULT_TARGET ${PROJECT_NAME})
	# set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_DEFAULT_TARGET ${PROJECT_NAME})
    set_target_properties(${PROJECT_NAME} PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${OUT_RUN_PATH})
    set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "SSL_xor")

    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "/GL")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/LTCG")
endif()