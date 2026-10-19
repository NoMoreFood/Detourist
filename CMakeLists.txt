cmake_minimum_required(VERSION 3.28)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Configure in a separate build directory.")
endif()
set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION_MAXIMUM "10.0.26100.0" CACHE STRING "Windows SDK compatible with PHNT")
project(Detourist LANGUAGES C CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(detourist_warnings /W4 /WX /permissive- /utf-8)
set(detourist_cxx_options ${detourist_warnings} /EHsc)
include(FetchContent)

FetchContent_Declare(detours
    URL https://codeload.github.com/microsoft/Detours/zip/e4bfd6b03e50de46b47abfbd1e46b384f0c5f833
    URL_HASH SHA256=fef0b17c5c3c9356fb8ba7366a3b196149daadd131fb6a92abeda1cb4d3b9b85
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
    URL_HASH SHA256=0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(phnt
    URL https://codeload.github.com/winsiderss/phnt/zip/53fbbdc5b5d2b08761db1c7b26bfa8c820924356
    URL_HASH SHA256=bbb442d47863cb189bf873e34a1a9a45c4a6f44c9d1aa4b670a7d4a2fa5c871d
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(detours sqlite phnt json)

# Transaction nodes must not allocate on a heap owned by a suspended target thread.
file(READ "${detours_SOURCE_DIR}/src/detours.cpp" detours_core)
string(REPLACE "\r\n" "\n" detours_core "${detours_core}")
foreach(node DetourThread DetourOperation)
    set(declaration "struct ${node}\n{")
    string(FIND "${detours_core}" "${declaration}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "Cannot isolate Detours transaction allocation: ${node}")
    endif()
    string(REPLACE "${declaration}" "struct ${node} : DetouristTransactionAllocation\n{"
        detours_core "${detours_core}")
endforeach()
# A thread that exited after enumeration no longer needs its instruction pointer translated.
set(detours_suspend "    if (SuspendThread(hThread) == (DWORD)-1) {\n        error = GetLastError();")
string(FIND "${detours_core}" "${detours_suspend}" position)
if(position EQUAL -1)
    message(FATAL_ERROR "Cannot handle exited Detours transaction threads.")
endif()
string(REPLACE "${detours_suspend}"
    [=[    if (SuspendThread(hThread) == (DWORD)-1) {
        error = GetLastError();
        if (DetouristTransactionThreads::Terminated(hThread)) {
            delete t;
            return NO_ERROR;
        }]=] detours_core "${detours_core}")
# The transaction owns peer suspension so callers cannot publish hooks against a stale thread list.
set(detours_commit "    // Common variables.\n    DetourOperation *o;")
string(FIND "${detours_core}" "${detours_commit}" position)
if(position EQUAL -1)
    message(FATAL_ERROR "Cannot isolate Detours commit thread suspension.")
endif()
string(REPLACE "${detours_commit}"
    [=[    DetouristTransactionThreads threads;
    if (s_pPendingOperations != NULL) {
        LONG error = threads.Suspend(DetourUpdateThread);
        if (error != NO_ERROR) {
            DetourTransactionAbort();
            return error;
        }
    }

    // Common variables.
    DetourOperation *o;]=] detours_core "${detours_core}")
string(REPLACE "#include \"detours.h\"" "#include \"detours.h\"\n#include \"DetoursAllocation.h\""
    detours_core "${detours_core}")
file(WRITE "${CMAKE_BINARY_DIR}/detours-core.cpp" "${detours_core}")
add_library(detours STATIC
    ${CMAKE_BINARY_DIR}/detours-core.cpp ${detours_SOURCE_DIR}/src/modules.cpp
    ${detours_SOURCE_DIR}/src/disasm.cpp ${detours_SOURCE_DIR}/src/image.cpp
    ${detours_SOURCE_DIR}/src/creatwth.cpp ${detours_SOURCE_DIR}/src/disolx86.cpp
    ${detours_SOURCE_DIR}/src/disolx64.cpp ${detours_SOURCE_DIR}/src/disolia64.cpp
    ${detours_SOURCE_DIR}/src/disolarm.cpp ${detours_SOURCE_DIR}/src/disolarm64.cpp)
target_include_directories(detours PUBLIC ${detours_SOURCE_DIR}/src)
target_include_directories(detours PRIVATE Source/agent)
target_link_libraries(detours PRIVATE ntdll)
set_target_properties(detours PROPERTIES CXX_STANDARD 17)
target_compile_options(detours PRIVATE /W0 /permissive)
add_library(sqlite STATIC ${sqlite_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite PUBLIC ${sqlite_SOURCE_DIR})
target_compile_definitions(sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_DQS=0 SQLITE_OMIT_LOAD_EXTENSION SQLITE_DEFAULT_WAL_SYNCHRONOUS=1)
target_compile_options(sqlite PRIVATE /W0)
add_library(DetouristSqlite SHARED ${sqlite_SOURCE_DIR}/sqlite3.c)
target_compile_definitions(DetouristSqlite PRIVATE "SQLITE_API=__declspec(dllexport)" SQLITE_THREADSAFE=1
    SQLITE_DEFAULT_MEMSTATUS=0 SQLITE_DQS=0 SQLITE_OMIT_LOAD_EXTENSION)
target_compile_options(DetouristSqlite PRIVATE /W0)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(detourist_generated "${CMAKE_BINARY_DIR}/generated")
set(detourist_catalog "${CMAKE_SOURCE_DIR}/Source/catalog/ApiCatalog.sqlite")
add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/bin/Release/ApiCatalog.sqlite"
        "${CMAKE_BINARY_DIR}/bin/Debug/ApiCatalog.sqlite"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bin/Release" "${CMAKE_BINARY_DIR}/bin/Debug"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${detourist_catalog}"
        "${CMAKE_BINARY_DIR}/bin/Release/ApiCatalog.sqlite"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${detourist_catalog}"
        "${CMAKE_BINARY_DIR}/bin/Debug/ApiCatalog.sqlite"
    DEPENDS "${detourist_catalog}" VERBATIM)
add_custom_target(detourist_catalog_stage DEPENDS "${CMAKE_BINARY_DIR}/bin/Release/ApiCatalog.sqlite"
    "${CMAKE_BINARY_DIR}/bin/Debug/ApiCatalog.sqlite")
set(detourist_builtin_catalogs "${detourist_generated}/CoreCatalog.inc" "${detourist_generated}/ComCatalog.inc"
    "${detourist_generated}/NativeCatalog.inc" "${detourist_generated}/Win32uCatalog.inc"
    "${detourist_generated}/Win32Headers.inc" "${detourist_generated}/Win32Bindings.h"
    "${detourist_generated}/NetApiRecordLayouts.h" "${detourist_generated}/NetApiRecordLayoutAssertions.h"
    "${detourist_generated}/ReplicationRecordLayouts.h")
get_filename_component(detourist_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
get_filename_component(detourist_msvc_include "${detourist_compiler_directory}/../../../include" ABSOLUTE)
set(detourist_sdk_include "C:/Program Files (x86)/Windows Kits/10/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
set(detourist_builtin_stamp "${detourist_generated}/BuiltinCatalogs.stamp")
add_custom_command(OUTPUT "${detourist_builtin_stamp}" BYPRODUCTS ${detourist_builtin_catalogs}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/Build/Scripts/GenerateBuiltinCatalogs.py"
        --output-dir "${detourist_generated}" --pointer-size "${CMAKE_SIZEOF_VOID_P}"
        --catalog "${detourist_catalog}"
    COMMAND ${CMAKE_COMMAND} -E touch "${detourist_builtin_stamp}"
    DEPENDS "${detourist_catalog}" Build/Scripts/GenerateBuiltinCatalogs.py
    VERBATIM)
add_custom_target(detourist_builtin_catalogs DEPENDS "${detourist_builtin_stamp}")

add_library(detourist_common STATIC Source/common/Transport.cpp Source/common/CaptureValues.cpp
    Source/common/CatalogCaptureValues.cpp
    Source/common/AsyncIo.cpp Source/common/RpcCapture.cpp Source/common/RpcFormats.cpp Source/common/RpcMarshal.cpp
    Source/common/ApiCategories.cpp
    Source/common/CatalogView.cpp)
add_dependencies(detourist_common detourist_builtin_catalogs)
set_source_files_properties(Source/common/CaptureValues.cpp PROPERTIES COMPILE_OPTIONS /EHa)
target_include_directories(detourist_common PUBLIC Source/common "${CMAKE_BINARY_DIR}/generated")
target_include_directories(detourist_common SYSTEM PRIVATE "${phnt_SOURCE_DIR}")
target_link_libraries(detourist_common PUBLIC ntdll)
target_compile_definitions(detourist_common PUBLIC UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00 WINVER=0x0A00)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(detourist_assembly_suffix 32)
endif()
add_library(detourist_arguments STATIC Source/common/InvokeArguments${detourist_assembly_suffix}.asm
    Source/agent/ExportHooks${detourist_assembly_suffix}.asm
    Source/agent/AsyncCallbacks${detourist_assembly_suffix}.asm)
add_library(DetouristAgent SHARED Source/agent/Agent.cpp Source/agent/Hooks.cpp Source/agent/NativeHooks.cpp
    Source/agent/ExportHooks.cpp Source/agent/AsyncCallbacks.cpp Source/agent/StackCapture.cpp
    Source/agent/NativeGateway${detourist_assembly_suffix}.cpp
    Source/agent/Win32Hooks.cpp Source/agent/Win32uHooks.cpp Source/agent/ComHooks.cpp Source/agent/ManagedBridge.cpp
    Source/agent/ModuleHooks.cpp Source/common/SdkCapture.cpp)
target_include_directories(DetouristAgent SYSTEM PRIVATE ${phnt_SOURCE_DIR})
target_link_libraries(DetouristAgent PRIVATE detourist_common detourist_arguments detours advapi32)
set_target_properties(DetouristAgent PROPERTIES PREFIX "")
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_sources(DetouristAgent PRIVATE Source/agent/Agent32.def)
endif()
add_library(detourist_capture STATIC Source/capture/Session.cpp Source/capture/TraceStore.cpp
    Source/capture/TraceView.cpp Source/capture/Symbols.cpp Source/capture/Inventory.cpp Source/capture/ApiCatalog.cpp)
target_include_directories(detourist_capture PUBLIC Source/capture)
target_link_libraries(detourist_capture PUBLIC detourist_common sqlite psapi comctl32 ole32 dbghelp)
add_library(DetouristSpy SHARED Source/spy/SpyHook.cpp)
target_include_directories(DetouristSpy PRIVATE Source/common)
target_compile_definitions(DetouristSpy PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_link_libraries(DetouristSpy PRIVATE user32)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_sources(DetouristSpy PRIVATE Source/spy/SpyHook32.def)
    set_target_properties(DetouristSpy PROPERTIES OUTPUT_NAME DetouristSpy32)
else()
    set_target_properties(DetouristSpy PROPERTIES OUTPUT_NAME DetouristSpy64)
endif()
add_executable(DetouristCollector Source/collector/Collector.cpp Source/collector/WindowSpy.cpp)
target_link_libraries(DetouristCollector PRIVATE detourist_capture nlohmann_json::nlohmann_json)
add_dependencies(DetouristCollector DetouristAgent DetouristSqlite DetouristSpy detourist_catalog_stage)
set(detourist_extended_default ON)
option(DETOURIST_BUILD_PROFILER "Build the CLR profiling component" ${detourist_extended_default})
option(DETOURIST_BUILD_MANAGED_DEBUGGER "Build the managed debugger attachment component" ON)
if(DETOURIST_BUILD_PROFILER)
    add_subdirectory(Source/profiler)
    target_sources(detourist_capture PRIVATE Source/capture/ManagedAttach.cpp)
    target_include_directories(detourist_capture PRIVATE Source/profiler)
    target_include_directories(detourist_capture SYSTEM PRIVATE ${DETOURIST_CLR_INCLUDE})
    target_link_libraries(detourist_capture PRIVATE ${DETOURIST_CLR_GUIDS} bcrypt)
    target_compile_definitions(detourist_capture PRIVATE DETOURIST_BUILD_PROFILER=1)
    add_dependencies(DetouristCollector DetouristProfiler)
    if(DETOURIST_BUILD_MANAGED_DEBUGGER)
        target_sources(detourist_capture PRIVATE Source/capture/ManagedDebugger.cpp Source/profiler/ManagedMetadata.cpp)
        target_link_libraries(detourist_capture PRIVATE nlohmann_json::nlohmann_json)
        target_link_libraries(detourist_capture PRIVATE detours)
        target_compile_definitions(detourist_capture PRIVATE DETOURIST_BUILD_MANAGED_DEBUGGER=1)
        add_executable(DetouristManagedDebugger Source/capture/ManagedDebuggerHost.cpp)
        target_link_libraries(DetouristManagedDebugger PRIVATE detourist_capture)
        target_compile_options(DetouristManagedDebugger PRIVATE ${detourist_cxx_options})
        add_dependencies(DetouristCollector DetouristManagedDebugger)
        install(TARGETS DetouristManagedDebugger RUNTIME DESTINATION .)
    endif()
endif()

include(CTest)
add_subdirectory(Source/instruction)
if(BUILD_TESTING)
    # Paired scenarios run with identical arguments and scheduling on each capture engine.
    function(detourist_add_test name timeout)
        cmake_parse_arguments(PARSE_ARGV 2 test "SERIAL;INSTRUCTIONS;INSPECTOR;DESKTOP" "" "")
        if(test_INSPECTOR)
            list(APPEND test_UNPARSED_ARGUMENTS --inspector "${detourist_desktop_test_assembly}")
        endif()
        add_test(NAME ${name} COMMAND ${test_UNPARSED_ARGUMENTS})
        set(tests ${name})
        if(test_INSTRUCTIONS AND DETOURIST_BUILD_INSTRUCTION_ENGINE)
            add_test(NAME ${name}_instructions COMMAND ${test_UNPARSED_ARGUMENTS} --instructions)
            list(APPEND tests ${name}_instructions)
        endif()
        set_tests_properties(${tests} PROPERTIES TIMEOUT ${timeout} RUN_SERIAL ${test_SERIAL})
        if(test_DESKTOP OR test_INSPECTOR)
            set_tests_properties(${tests} PROPERTIES FIXTURES_REQUIRED desktop_assembly)
        endif()
    endfunction()

    function(detourist_python_test name timeout script)
        detourist_add_test(${name} ${timeout} ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/Test/${script}" ${ARGN})
    endfunction()

    find_program(DETOURIST_DOTNET dotnet REQUIRED)
    set(detourist_desktop_test_assembly
        "${CMAKE_BINARY_DIR}/desktop-tests/$<CONFIG>/net10.0-windows/Detourist.Desktop.Tests.dll")
    set(desktop_native_arguments)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        list(APPEND desktop_native_arguments "-p:DetouristNativeDir=$<TARGET_FILE_DIR:DetouristCollector>")
    endif()
    add_test(NAME desktop_setup COMMAND "${DETOURIST_DOTNET}" build
        "${CMAKE_SOURCE_DIR}/Test/Desktop/Detourist.Desktop.Tests.csproj" --configuration $<CONFIG> --nologo
        ${desktop_native_arguments} "-p:DetouristBuildDirectory=${CMAKE_BINARY_DIR}"
        "-p:BaseOutputPath=${CMAKE_BINARY_DIR}/desktop-tests/")
    set_tests_properties(desktop_setup PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE FIXTURES_SETUP desktop_assembly)

    add_executable(DetouristHotPathTests Test/HotPathTests.cpp)
    target_link_libraries(DetouristHotPathTests PRIVATE detourist_common)
    target_compile_options(DetouristHotPathTests PRIVATE ${detourist_cxx_options})
    add_test(NAME capture_hot_paths COMMAND DetouristHotPathTests)
    set_tests_properties(capture_hot_paths PROPERTIES TIMEOUT 30)
    include(Test/Tests.cmake)
    include(Test/CoverageTests.cmake)
    include(Test/HookTests.cmake)
    add_executable(DetouristWindowSpyTarget Test/WindowSpyTarget.cpp)
    target_compile_definitions(DetouristWindowSpyTarget PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_compile_options(DetouristWindowSpyTarget PRIVATE ${detourist_cxx_options})
    target_link_libraries(DetouristWindowSpyTarget PRIVATE user32)
    add_dependencies(DetouristWindowSpyTarget DetouristCollector)
    add_test(NAME window_spy COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Test/WindowSpyTests.py
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristWindowSpyTarget>)
    set_tests_properties(window_spy PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    add_executable(DetouristComProxyTests Test/ComProxyTests.cpp)
    target_link_libraries(DetouristComProxyTests PRIVATE detourist_test_support ole32 uuid)
    target_compile_options(DetouristComProxyTests PRIVATE ${detourist_cxx_options})
    add_dependencies(DetouristComProxyTests DetouristCollector)
    add_test(NAME com_shared_proxies COMMAND DetouristComProxyTests $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(com_shared_proxies PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE LABELS "com;abi")
    add_test(NAME target_exit_codes COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Test/ExitCodeTests.py
        $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(target_exit_codes PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)

    # Configure each CRT instance used by tests without changing normal Debug application behavior.
    set(unattended_targets DetouristAgent DetouristCollector DetouristProfiler DetouristManagedDebugger
        DetouristSpy DetouristSqlite)
    get_property(root_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(target IN LISTS root_targets)
        get_target_property(type ${target} TYPE)
        if(NOT type STREQUAL "EXECUTABLE")
            continue()
        endif()
        get_target_property(sources ${target} SOURCES)
        foreach(source IN LISTS sources)
            if(source MATCHES "(^|/)Test/[^/]+[.]cpp$")
                list(APPEND unattended_targets ${target})
                break()
            endif()
        endforeach()
    endforeach()
    foreach(target IN LISTS unattended_targets)
        if(TARGET ${target})
            target_sources(${target} PRIVATE "$<$<CONFIG:Debug>:${CMAKE_SOURCE_DIR}/Test/UnattendedTests.cpp>")
        endif()
    endforeach()
    add_test(NAME unattended_debug_assertion COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/Test/UnattendedTests.py $<TARGET_FILE:DetouristTestTarget> CONFIGURATIONS Debug)
    set_tests_properties(unattended_debug_assertion PROPERTIES TIMEOUT 30)
    get_property(root_tests DIRECTORY PROPERTY TESTS)
    set_property(TEST ${root_tests} APPEND PROPERTY ENVIRONMENT "DETOURIST_TEST_UNATTENDED=1")
endif()

foreach(target detourist_common detourist_capture DetouristAgent DetouristCollector DetouristSpy
    DetouristTestTarget DetouristCaptureTests DetouristHookTests)
    if(TARGET ${target})
        target_compile_options(${target} PRIVATE ${detourist_warnings})
        if(target STREQUAL "DetouristAgent")
            target_compile_options(${target} PRIVATE /EHa /bigobj)
        else()
            target_compile_options(${target} PRIVATE /EHsc)
        endif()
    endif()
endforeach()
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/licenses")
configure_file(${detours_SOURCE_DIR}/LICENSE.md ${CMAKE_BINARY_DIR}/licenses/Detours.txt COPYONLY)
configure_file(LICENSE ${CMAKE_BINARY_DIR}/licenses/Detourist.txt COPYONLY)
file(WRITE "${CMAKE_BINARY_DIR}/licenses/SQLite.txt"
    "SQLite is in the public domain.\nhttps://www.sqlite.org/copyright.html\n")
configure_file(${phnt_SOURCE_DIR}/LICENSE ${CMAKE_BINARY_DIR}/licenses/PHNT.txt COPYONLY)
configure_file(${json_SOURCE_DIR}/LICENSE.MIT ${CMAKE_BINARY_DIR}/licenses/JSON.txt COPYONLY)
install(TARGETS DetouristCollector DetouristAgent DetouristSqlite DetouristSpy RUNTIME DESTINATION .)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(FILES "${detourist_catalog}" DESTINATION .)
endif()
install(DIRECTORY ${CMAKE_BINARY_DIR}/licenses/ DESTINATION licenses)
