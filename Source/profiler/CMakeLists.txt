enable_language(ASM_MASM)
find_path(DETOURIST_CLR_INCLUDE corprof.h
    PATHS "$ENV{ProgramFiles\(x86\)}/Windows Kits/NETFXSDK/4.8.1/Include/um"
          "$ENV{ProgramFiles\(x86\)}/Windows Kits/NETFXSDK/4.8/Include/um"
    REQUIRED)
set(detourist_clr_architecture x64)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(detourist_clr_architecture x86)
endif()
find_library(DETOURIST_CLR_GUIDS corguids
    PATHS "$ENV{ProgramFiles\(x86\)}/Windows Kits/NETFXSDK/4.8.1/Lib/um/${detourist_clr_architecture}"
          "$ENV{ProgramFiles\(x86\)}/Windows Kits/NETFXSDK/4.8/Lib/um/${detourist_clr_architecture}"
    REQUIRED)
add_library(DetouristProfiler SHARED Profiler.cpp ManagedMetadata.cpp ManagedInstrumentation.cpp
    ProfilerHooks${detourist_assembly_suffix}.asm Profiler.def)
add_dependencies(DetouristProfiler detourist_builtin_catalogs)
target_include_directories(DetouristProfiler PRIVATE ${CMAKE_SOURCE_DIR}/Source/common
    "${CMAKE_BINARY_DIR}/generated")
target_include_directories(DetouristProfiler SYSTEM PRIVATE ${DETOURIST_CLR_INCLUDE})
target_compile_definitions(DetouristProfiler PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(DetouristProfiler PRIVATE
    "$<$<COMPILE_LANGUAGE:CXX>:${detourist_warnings};/EHa>")
target_link_libraries(DetouristProfiler PRIVATE ${DETOURIST_CLR_GUIDS} bcrypt ole32 nlohmann_json::nlohmann_json)
set_target_properties(DetouristProfiler PROPERTIES PREFIX "")
install(TARGETS DetouristProfiler RUNTIME DESTINATION .)
