# 输入路径
set(SDK_DIR
    # ${UPMODELEDITOR_ROOT}/SDK/me-sdk
    # ${UPMODELEDITOR_ROOT}/SDK/sdk
    # ${UPMODELEDITOR_ROOT}/SDK/wvm-sdk
)
message("SDK_DIR = ${SDK_DIR}")

set(SDK_INCLUDE
	# $ENV{UPS_Library}
    # ${UPMODELEDITOR_ROOT}/SDK/me-sdk/include
    # ${UPMODELEDITOR_ROOT}/SDK/sdk/include
    # ${UPMODELEDITOR_ROOT}/SDK/wvm-sdk/include
)

set(SDK_LIB_DIRECTORY
    # ${UPMODELEDITOR_ROOT}/SDK/me-sdk/lib
    # ${UPMODELEDITOR_ROOT}/SDK/sdk/lib
    # ${UPMODELEDITOR_ROOT}/SDK/wvm-sdk/lib
)

# 输出路径
set(OUT ${CMAKE_CURRENT_SOURCE_DIR}/../out)
message("out = ${OUT}")
set(OUT_LIB_PATH ${OUT}/lib)
set(OUT_DLL_PATH ${OUT}/bin.x64)
set(OUT_INCLUDE_PATH ${OUT}/include)
set(OUT_RUN_PATH ${OUT}/bin.x64)

# 安装与查找
string(REPLACE "\\" "/" INSTALL_PREFIX ${OUT})
set(CMAKE_INSTALL_PREFIX ${INSTALL_PREFIX})
message("CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")

set(CMAKE_PREFIX_PATH ${INSTALL_PREFIX}/lib/config)
message("CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")

# qt moudle
set(QT6_MOUDLES
    QT6::Core
	QT6::Widgets
    QT6::Gui
)

# libevent
set(Libevent_MOUDLES
	libevent::core
	libevent::extra
	libevent::openssl
)

# 
set(SSL_MOUDLES 
	OpenSSL::SSL 
	OpenSSL::Crypto
)

# 获取当前目录下源码和头文件
macro(get_src_include)
    aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/src SRC)
    aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/Source SOURCE)

    list(APPEND SRC ${SOURCE})

    # message("SRC = ${SRC}")
    FILE(GLOB H_FILE_I ${CMAKE_CURRENT_LIST_DIR}/include/*.h)
    FILE(GLOB UI_FILES ${CMAKE_CURRENT_LIST_DIR}/src/*.ui)

    if(RC_FILE)
        source_group("Resource Files" FILES ${RC_FILE})
    endif()

    if(UI_FILES)
        qt_wrap_ui(UIC_HEADER ${UI_FILES})
        source_group("Resource Files" FILES ${UI_FILES})
        source_group("Generate Files" FILES ${UIC_HEADER})
    endif()

    if(QRC_SOURCE_FILES)
        qt6_add_resources(QRC_FILES ${QRC_SOURCE_FILES})
        qt6_wrap_cpp()
        source_group("Resource Files" FILES ${QRC_SOURCE_FILES})
    endif()
endmacro()

# GCC 设置忽略编译告警
macro(remove_warnings)
    add_definitions(-Wno-unused-value -Wno-unknown-pragmas -Wno-sequence-point
        -Wno-delete-non-virtual-dtor -Wno-unused-but-set-variable
        -Wno-sign-compare -Wno-unused-variable -Wno-return-local-addr
        -Wno-unused-function -Wno-deprecated-declarations)
endmacro()

# 配置编译参数
macro(set_cpp name)
    target_link_directories(${name} PRIVATE ${SDK_LIB_DIRECTORY})

    # message("Qt6_FOUND = ${Qt6_FOUND}")
    # target_link_libraries(${name} ${QT6_MOUDLES})
	
	# message("Libevent_FOUND = ${Libevent_FOUND}")
    # target_link_libraries(${name} ${Libevent_MOUDLES})
	
	message("OpenSSL_FOUND = ${OpenSSL_FOUND}")
	# message("SSL_MOUDLES = ${SSL_MOUDLES}")
	target_link_libraries(${name} PRIVATE ${SSL_MOUDLES})

    message("DPS_INCLUDES = ${DPS_INCLUDES}")

    # 路径被两次引用 1 编译slib库时 2 install export写入config时
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> # install时为空,只有编译时有值
        $<INSTALL_INTERFACE:include> # 只有install时有值 /home/hdb/xcpp/include
    )

    target_include_directories(${name} PRIVATE
        ${DPS_INCLUDES}
        ${SDK_INCLUDE}
    )
    set(DPS_INCLUDES "")

    message("DPS_TARGETS = ${DPS_TARGETS}")

    if(DPS_TARGETS)
        add_dependencies(${name} ${DPS_TARGETS})

        if(TEST_FIND)
            foreach(target IN LISTS DPS_TARGETS)
                message("   ++++++++++++++++++++++${target}+++++++++++++++++++++++")
                find_package(${target} ${version})
                message("   ${target}_FOUND = ${${target}_FOUND}")

                if(NOT ${target}_FOUND)
                    continue()
                endif()

                get_target_property(inc ${target} INTERFACE_INCLUDE_DIRECTORIES)
                message("   INTERFACE_INCLUDE_DIRECTORIES = ${inc}")
                message("   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            endforeach()
        endif()

        target_link_libraries(${name} PRIVATE ${DPS_TARGETS})

        set(DPS_TARGETS "")
    endif()

    message("DPS_LIBRARYS = ${DPS_LIBRARYS}")
    target_link_libraries(${name} PRIVATE ${DPS_LIBRARYS})
    set(DPS_LIBRARYS "")

    target_compile_features(${name} PRIVATE
        cxx_std_20
    )

    target_link_options(${name} PRIVATE
        -D2:-AllowCompatibleILVersions
    )

    target_compile_definitions(${name} PUBLIC
        -DUNICODE
        -D_UNICODE
        -DNOMINMAX
        -D_USE_MATH_DEFINES
    )

    if(MSVC)
        set_target_properties(${name} PROPERTIES
            COMPILE_FLAGS "/Zc:wchar_t"	# 是
			#COMPILE_FLAGS "/Zc:wchar_t-" #否
        )

        # set_target_properties(${name} PROPERTIES
        # COMPILE_FLAGS "-bigobj"
        # )
        set_target_properties(${PROJECT_NAME} PROPERTIES
            MSVC_RUNTIME_LIBRARY MultiThreadedDLL
        )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "")
        set(CMAKE_BUILD_TYPE RelWithDebInfo)
    endif()

    set(CONF_TYPES Debug Release RelWithDebInfo MinSizeRel)
    list(APPEND CONF_TYPES "")

    foreach(type IN LISTS CONF_TYPES)
        set(conf "")

        if(type)
            string(TOUPPER _${type} conf)
        endif()

        set_target_properties(${name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY${conf} ${OUT_RUN_PATH} # dll  exe 执行程序
            LIBRARY_OUTPUT_DIRECTORY${conf} ${OUT_LIB_PATH} # .so .dylib
            ARCHIVE_OUTPUT_DIRECTORY${conf} ${OUT_LIB_PATH} # .lib .a
            PDB_OUTPUT_DIRECTORY${conf} ${OUT_RUN_PATH} # pdb
        )
    endforeach()

    # set_target_properties(${name} PROPERTIES
    # DEBUG_POSTFIX "_d"
    # )
    set(debug_postfix "")

    if(WIN32)
        get_target_property(debug_postfix ${name} DEBUG_POSTFIX)
    endif()
endmacro()

# 配置库环境配置（兼容windows linux mac）
function(cpp_library name)
    message(STATUS "================ ${name} cpp_library =================")
    message("CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")
    option(${name}_SHARED "OFF is static cpp_library" ON)
    message("${name}_SHARED = ${${name}_SHARED}")
    option(TEST_FIND "ON is test find_pakage" OFF)

    set(TYPE STATIC)

    if(${name}_SHARED)
        set(TYPE SHARED)

        if(WIN32)
            set(WINDOWS_EXPORT_ALL_SYMBOLS ON)
        endif()
    endif()

    get_src_include()

    add_library(${name} ${TYPE}
        ${SRC}
        ${H_FILE_I}

        ${UI_FILES}
        ${UIC_HEADER}
        ${QRC_FILES}
    )

    if(NOT version)
        set(version 1.0)
    endif()

    set_cpp(${name})

    if(${name}_SHARED)
        target_compile_definitions(${name} PRIVATE ${name}_EXPORTS)
    else()
        target_compile_definitions(${name} PRIVATE ${name}_STATIC)
    endif()

    # 设置安装的头文件
    set_target_properties(${name} PROPERTIES
        PUBLIC_HEADER "${H_FILE_I}"
    )

    install(TARGETS ${name}
        EXPORT ${name}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
    )

    set(CONF_VER_DIR ${OUT_LIB_PATH}/config/${name}-${version})
    string(REPLACE "\\" "/" CONF_VER_DIR ${CONF_VER_DIR})

    # 支持find_package
    # 生成并安装配置文件
    instaLl(EXPORT ${name} FILE ${name}Config.cmake
        DESTINATION ${CONF_VER_DIR}
    )

    #
    # 版本文件
    set(CONF_VER_FILE
        ${OUT_LIB_PATH}/config/${name}-${version}/${name}ConfigVersion.cmake)

    string(REPLACE "\\" "/" CONF_VER_FILE ${CONF_VER_FILE})

    message("CONF_VER_FILE = ${CONF_VER_FILE}")
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        ${CONF_VER_FILE}
        VERSION ${version}
        COMPATIBILITY SameMajorVersion # 版本兼容问题
    )

    install(FILES ${CONF_VER_FILE}
        DESTINATION lib/config/${name}-${version}
    )

    message(STATUS "==================================================================")
endfunction()

function(cpp_execute name)
    message(STATUS "================ ${name} cpp_execute =================")
    get_src_include()

    # 添加执行程序
    add_executable(${name}
        ${SRC}
        ${H_FILE_I}
        ${UIC_HEADER}
        ${QRC_SOURCE_FILES}
        ${RC_FILE}
    )

    # 设置配置信息
    set_cpp(${name})

    # 第二种 链接的方式 推荐第一种
    math(EXPR size "${ARGC}-1")

    if(size GREATER 0)
        foreach(i RANGE 1 ${size})
            message("target_link_libraries ${ARGV${i}}")
            set(lib_name ${ARGV${i}})
            target_link_libraries(${name} ${lib_name}${debug_postfix})
        endforeach()
    endif()

    message(STATUS "==================================================================")
endfunction()
