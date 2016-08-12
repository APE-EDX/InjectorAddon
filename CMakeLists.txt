project(InjectorAddon)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    set(ARCH x64)
else ()
    set(ARCH ia32)
endif()

add_subdirectory(deps)

set(EXTERNAL_LIBRARIES "")
set(EXTERNAL_DIRS "")
if(UNIX)
    set(EXTERNAL_LIBRARIES "\"deps/hotpatch/src/libhotpatch_s.a\"")
    set(EXTERNAL_DIRS "\"${PROJECT_SOURCE_DIR}/build/deps/hotpatch/include\", \"${PROJECT_SOURCE_DIR}/deps/hotpatch/include\"")
endif()
configure_file(${PROJECT_SOURCE_DIR}/binding.gyp.in ${PROJECT_SOURCE_DIR}/binding.gyp)

add_custom_target(
    InjectorAddon-install ALL
    COMMAND npm install -g node-gyp
    DEPENDS hotpatch_s
)

add_custom_target(
    InjectorAddon-configure ALL
    COMMAND node-gyp configure --directory=${PROJECT_SOURCE_DIR} --target=1.3.0 --arch=${ARCH} --dist-url=https://atom.io/download/atom-shell
    DEPENDS InjectorAddon-install
)

add_custom_target(
    InjectorAddon-build ALL
    COMMAND node-gyp build --directory=${PROJECT_SOURCE_DIR} --target=1.3.0 --arch=${ARCH} --dist-url=https://atom.io/download/atom-shell
    DEPENDS InjectorAddon-configure
)

add_custom_target(
    InjectorAddon-copy ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/build/Release/injector.node ${PROJECT_SOURCE_DIR}/bin/${ARCH}/injector.node
    DEPENDS InjectorAddon-build
)
