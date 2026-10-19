if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_executable(DetouristMemoryCaptureTests Test/RuntimeTests.cpp)
    target_compile_definitions(DetouristMemoryCaptureTests PRIVATE DETOURIST_TEST_DetouristMemoryCaptureTests)
    target_compile_options(DetouristMemoryCaptureTests PRIVATE ${detourist_cxx_options})
    target_link_libraries(DetouristMemoryCaptureTests PRIVATE detourist_test_support detourist_common)
    add_test(NAME capture_memory_safety COMMAND DetouristMemoryCaptureTests)
    set_tests_properties(capture_memory_safety PROPERTIES TIMEOUT 15)
endif()

function(detourist_capture_rule_test fixture name)
    set(target Detourist${fixture}Tests)
    add_executable(${target} Test/${fixture}Tests.cpp)
    target_link_libraries(${target} PRIVATE detourist_common)
    target_compile_options(${target} PRIVATE ${detourist_cxx_options})
    add_test(NAME ${name} COMMAND ${target})
    set_tests_properties(${name} PROPERTIES TIMEOUT 15 LABELS "coverage;capture")
endfunction()

detourist_capture_rule_test(PrintDocumentCapture print_document_capture)
detourist_capture_rule_test(BufferRules buffer_capture_rules)
detourist_capture_rule_test(AuthzOperationsCapture authz_operations_capture)
detourist_capture_rule_test(EapErrorCapture eap_error_capture)
detourist_capture_rule_test(RtmCapture rtm_capture)

if(DETOURIST_BUILD_INSTRUCTION_ENGINE AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    find_program(detourist_legacy_midl midl.exe PATHS
        "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64" REQUIRED)
    set(detourist_legacy_rpc "${CMAKE_CURRENT_BINARY_DIR}/generated/RpcLegacyFixture")
    # Suppress the legacy mode warning, then restore normal diagnostics for the IDL.
    add_custom_command(OUTPUT "${detourist_legacy_rpc}.h" "${detourist_legacy_rpc}_c.c" "${detourist_legacy_rpc}_s.c"
        COMMAND "${detourist_legacy_midl}" /nologo /no_cpp /env win32 /W0 /Oi /W1 /no_robust
            /prefix client Client_ /prefix server Server_ /out "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${CMAKE_SOURCE_DIR}/Test/RpcLegacyFixture.idl"
        DEPENDS Test/RpcLegacyFixture.idl VERBATIM)
    add_executable(DetouristX86CatalogTests Test/X86CatalogTests.cpp Test/X86SehFixture.c
        "${detourist_legacy_rpc}.h" "${detourist_legacy_rpc}_c.c" "${detourist_legacy_rpc}_s.c")
    set_source_files_properties(Test/X86SehFixture.c PROPERTIES COMPILE_OPTIONS "/GS-;/Od;/Oy-")
    set_source_files_properties("${detourist_legacy_rpc}_c.c" PROPERTIES COMPILE_OPTIONS "/wd4100;/Od;/Oy-")
    target_include_directories(DetouristX86CatalogTests PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_link_libraries(DetouristX86CatalogTests PRIVATE detourist_test_support detourist_common rpcrt4)
    target_compile_options(DetouristX86CatalogTests PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:${detourist_cxx_options}>")
    add_dependencies(DetouristX86CatalogTests DetouristCollector)
    add_test(NAME x86_native_catalog COMMAND DetouristX86CatalogTests $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(x86_native_catalog PROPERTIES TIMEOUT 180 LABELS "coverage;catalog;abi")
endif()
if(DETOURIST_BUILD_INSTRUCTION_ENGINE AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(detourist_shared_imports)
    foreach(provider Comctl Shell Wininet)
        set(import_library "${CMAKE_CURRENT_BINARY_DIR}/generated/Shared${provider}.lib")
        add_custom_command(OUTPUT "${import_library}"
            COMMAND "${CMAKE_AR}" /nologo /machine:x64
                "/def:${CMAKE_SOURCE_DIR}/Test/Shared${provider}.def" "/out:${import_library}"
            DEPENDS "Test/Shared${provider}.def" VERBATIM)
        list(APPEND detourist_shared_imports "${import_library}")
    endforeach()
    detourist_capture_test(DetouristSharedOrdinalTests Test/SharedOrdinalTests.cpp ${detourist_shared_imports})
    target_link_libraries(DetouristSharedOrdinalTests PRIVATE detourist_test_support detourist_common
        gdi32 ${detourist_shared_imports})
    target_compile_options(DetouristSharedOrdinalTests PRIVATE ${detourist_cxx_options})
    add_test(NAME shared_ordinals COMMAND DetouristSharedOrdinalTests $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(shared_ordinals PROPERTIES TIMEOUT 180 LABELS "coverage;catalog;abi")
    detourist_capture_test(DetouristCoverageConvergenceTests Test/CoverageConvergenceTests.cpp)
    target_link_libraries(DetouristCoverageConvergenceTests PRIVATE detourist_test_support msrating)
    target_compile_options(DetouristCoverageConvergenceTests PRIVATE ${detourist_cxx_options})
    add_test(NAME coverage_convergence COMMAND DetouristCoverageConvergenceTests $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(coverage_convergence PROPERTIES TIMEOUT 240 LABELS "coverage;catalog")
endif()
add_library(DetouristModuleAliasFixture SHARED Test/ModuleAliasFixture.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_options(DetouristModuleAliasFixture PRIVATE /EXPORT:CRYPTO_memcmp
        /EXPORT:SSL_get_version /EXPORT:X3DAudioCalculate=_X3DAudioCalculate@20
        /EXPORT:D3DCompile=_D3DCompile@44 /EXPORT:D3DX11CreateFFT=_D3DX11CreateFFT@20)
endif()
add_library(DetouristPrivateHookFixture SHARED Test/ModuleAliasFixture.cpp)
target_compile_definitions(DetouristPrivateHookFixture PRIVATE DETOURIST_PRIVATE_HOTPATCH)
target_compile_options(DetouristPrivateHookFixture PRIVATE ${detourist_warnings})
target_link_options(DetouristPrivateHookFixture PRIVATE /FUNCTIONPADMIN:5 /INCREMENTAL:NO)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_options(DetouristPrivateHookFixture PRIVATE /hotpatch)
    target_link_options(DetouristPrivateHookFixture PRIVATE /EXPORT:D3DCompile=_D3DCompile@44)
endif()
add_executable(DetouristModuleAliasTests Test/ModuleAliasTests.cpp)
target_link_libraries(DetouristModuleAliasTests PRIVATE detourist_test_support detourist_capture)
target_compile_options(DetouristModuleAliasTests PRIVATE ${detourist_cxx_options})
add_dependencies(DetouristModuleAliasTests DetouristCollector DetouristModuleAliasFixture DetouristPrivateHookFixture)
add_test(NAME module_aliases COMMAND DetouristModuleAliasTests $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristModuleAliasFixture> "${detourist_catalog}" $<TARGET_FILE:DetouristPrivateHookFixture>)
set_tests_properties(module_aliases PROPERTIES TIMEOUT 120 LABELS "coverage;catalog;abi")
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    add_test(NAME module_aliases_instructions COMMAND DetouristModuleAliasTests $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristModuleAliasFixture> "${detourist_catalog}"
        $<TARGET_FILE:DetouristPrivateHookFixture> --instructions)
    set_tests_properties(module_aliases_instructions PROPERTIES TIMEOUT 120 LABELS "coverage;catalog;abi")
endif()

add_test(NAME catalog_architecture_rows COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Test/CatalogTests.py
    architecture_rows "${detourist_catalog}")
set_tests_properties(catalog_architecture_rows PROPERTIES TIMEOUT 60 LABELS "coverage;catalog")

foreach(suffix "" "_cross_architecture")
    set(child_arguments --suspended)
    set(token_arguments --startup-token)
    if(suffix)
        list(APPEND child_arguments --cross-architecture)
        list(APPEND token_arguments --cross-architecture)
    endif()
    add_test(NAME child_suspended_startup${suffix} COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/Test/ChildLifecycleTests.py $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristTestTarget> ${child_arguments})
    set_tests_properties(child_suspended_startup${suffix} PROPERTIES
        TIMEOUT 300 RUN_SERIAL TRUE SKIP_RETURN_CODE 77 LABELS "capture;children")
    if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
        add_test(NAME child_suspended_startup${suffix}_instructions COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/Test/ChildLifecycleTests.py $<TARGET_FILE:DetouristCollector>
            $<TARGET_FILE:DetouristTestTarget> ${child_arguments} --instructions)
        set_tests_properties(child_suspended_startup${suffix}_instructions PROPERTIES
            TIMEOUT 300 RUN_SERIAL TRUE SKIP_RETURN_CODE 77 LABELS "capture;children;instructions")
    endif()
    foreach(integrity "" "_low_integrity")
        set(token_mode_arguments ${token_arguments})
        if(integrity)
            list(APPEND token_mode_arguments --low-integrity)
        endif()
        add_test(NAME child_startup_token${integrity}${suffix} COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/Test/ChildLifecycleTests.py $<TARGET_FILE:DetouristCollector>
            $<TARGET_FILE:DetouristTestTarget> ${token_mode_arguments})
        set_tests_properties(child_startup_token${integrity}${suffix} PROPERTIES
            TIMEOUT 180 RUN_SERIAL TRUE SKIP_RETURN_CODE 77 LABELS "capture;children;security")
        if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
            add_test(NAME child_startup_token${integrity}${suffix}_instructions COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/Test/ChildLifecycleTests.py $<TARGET_FILE:DetouristCollector>
                $<TARGET_FILE:DetouristTestTarget> ${token_mode_arguments} --instructions)
            set_tests_properties(child_startup_token${integrity}${suffix}_instructions PROPERTIES
                TIMEOUT 180 RUN_SERIAL TRUE SKIP_RETURN_CODE 77 LABELS "capture;children;security;instructions")
        endif()
    endforeach()
endforeach()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(DetouristArrayArgumentTests Test/NativeContracts.cpp)
    target_compile_definitions(DetouristArrayArgumentTests PRIVATE DETOURIST_TEST_DetouristArrayArgumentTests)
    target_compile_options(DetouristArrayArgumentTests PRIVATE ${detourist_cxx_options})
    target_link_libraries(DetouristArrayArgumentTests PRIVATE detourist_test_support)
    add_dependencies(DetouristArrayArgumentTests DetouristCollector)
    add_test(NAME array_argument_abi COMMAND DetouristArrayArgumentTests $<TARGET_FILE:DetouristCollector>)
    set_tests_properties(array_argument_abi PROPERTIES TIMEOUT 90 LABELS "coverage;catalog;abi")
    if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
        add_test(NAME array_argument_abi_instructions COMMAND DetouristArrayArgumentTests
            $<TARGET_FILE:DetouristCollector> --instructions)
        set_tests_properties(array_argument_abi_instructions PROPERTIES TIMEOUT 90 LABELS "coverage;catalog;abi")
    endif()
endif()

set(detourist_fixture_base 0x180000000)
set(detourist_symbol_assembly Test/SymbolSyscall.asm)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_test(NAME x86_catalog_metadata COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Test/CatalogTests.py
        x86_metadata "${detourist_catalog}")
    set_tests_properties(x86_catalog_metadata PROPERTIES TIMEOUT 30 LABELS "coverage;catalog;abi")
    set(detourist_fixture_base 0x50000000)
    set(detourist_symbol_assembly Test/SymbolSyscall32.asm)
endif()
foreach(name First Second)
    add_library(DetouristModule${name} SHARED Test/ModuleLifetimeFixture.cpp)
    target_compile_definitions(DetouristModule${name} PRIVATE "DETOURIST_MODULE_MESSAGE=\"${name}\"")
    target_link_options(DetouristModule${name} PRIVATE /DYNAMICBASE:NO /BASE:${detourist_fixture_base})
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(DetouristModule${name} PRIVATE /EXPORT:ModuleLifetimeCall=_ModuleLifetimeCall@4)
    endif()
endforeach()
add_executable(DetouristModuleLifetimeTests Test/ModuleLifetimeTests.cpp)
target_link_libraries(DetouristModuleLifetimeTests PRIVATE detourist_test_support detourist_capture)
target_compile_options(DetouristModuleLifetimeTests PRIVATE ${detourist_cxx_options})
add_dependencies(DetouristModuleLifetimeTests DetouristCollector DetouristModuleFirst DetouristModuleSecond)
add_test(NAME module_lifetimes COMMAND DetouristModuleLifetimeTests $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristModuleFirst> $<TARGET_FILE:DetouristModuleSecond>)
set_tests_properties(module_lifetimes PROPERTIES TIMEOUT 180 LABELS "coverage;lifecycle")
if(TARGET DetouristProviderComTests)
    add_test(NAME provider_availability COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/Test/ProviderAvailabilityTests.py
        $<TARGET_FILE:DetouristProviderComTests> $<TARGET_FILE:DetouristModuleFirst>)
    set_tests_properties(provider_availability PROPERTIES TIMEOUT 90 LABELS "coverage;providers")
endif()

add_executable(DetouristAsyncIoTests Test/AsyncIoTests.cpp)
target_link_libraries(DetouristAsyncIoTests PRIVATE detourist_test_support detourist_capture ws2_32)
target_compile_options(DetouristAsyncIoTests PRIVATE ${detourist_cxx_options})
# Native APC callbacks must not resolve through unaligned incremental-link thunks.
target_link_options(DetouristAsyncIoTests PRIVATE /INCREMENTAL:NO)
add_dependencies(DetouristAsyncIoTests DetouristCollector)
add_test(NAME async_io COMMAND DetouristAsyncIoTests $<TARGET_FILE:DetouristCollector>
    --inspector "${detourist_desktop_test_assembly}")
add_test(NAME async_io_lifecycle COMMAND DetouristAsyncIoTests $<TARGET_FILE:DetouristCollector> --lifecycle)
set_tests_properties(async_io async_io_lifecycle PROPERTIES TIMEOUT 240 LABELS "coverage;io")
set_tests_properties(async_io PROPERTIES FIXTURES_REQUIRED desktop_assembly)

foreach(name First Second)
    add_library(DetouristSymbol${name} SHARED Test/SymbolFixture.cpp ${detourist_symbol_assembly})
    target_compile_definitions(DetouristSymbol${name} PRIVATE SYMBOL_INNER=Symbol${name}Inner
        SYMBOL_OUTER=Symbol${name}Outer "SYMBOL_LABEL=\"${name}\"")
    target_compile_options(DetouristSymbol${name} PRIVATE /Zi)
    target_link_options(DetouristSymbol${name} PRIVATE /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DYNAMICBASE:NO
        /BASE:${detourist_fixture_base})
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_options(DetouristSymbol${name} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/Oy->)
        target_link_options(DetouristSymbol${name} PRIVATE /EXPORT:SymbolCapture=_SymbolCapture@8
            /EXPORT:SymbolLocked=_SymbolLocked@4 /EXPORT:SymbolDynamic=_SymbolDynamic@8)
    endif()
endforeach()
add_executable(DetouristSymbolTests Test/SymbolTests.cpp)
target_link_libraries(DetouristSymbolTests PRIVATE detourist_test_support detourist_capture)
target_compile_options(DetouristSymbolTests PRIVATE ${detourist_cxx_options})
add_dependencies(DetouristSymbolTests DetouristCollector DetouristSymbolFirst DetouristSymbolSecond)
add_test(NAME symbols COMMAND DetouristSymbolTests $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristSymbolFirst> $<TARGET_FILE:DetouristSymbolSecond>
    $<TARGET_PDB_FILE:DetouristSymbolFirst> $<TARGET_PDB_FILE:DetouristSymbolSecond>
    --inspector "${detourist_desktop_test_assembly}")
set_tests_properties(symbols PROPERTIES TIMEOUT 240 LABELS "coverage;symbols" FIXTURES_REQUIRED desktop_assembly)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_test(NAME symbols_attach COMMAND DetouristSymbolTests $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristSymbolFirst> --attach)
    set_tests_properties(symbols_attach PROPERTIES TIMEOUT 240 LABELS "coverage;symbols")
endif()

include(Test/RpcTests.cmake)

add_executable(DetouristPublishedApiTests Test/PublishedApiTests.cpp Test/DirectSoundProperties.c)
target_link_libraries(DetouristPublishedApiTests PRIVATE detourist_test_support detourist_capture
    ole32 uuid windowscodecs)
target_compile_options(DetouristPublishedApiTests PRIVATE ${detourist_cxx_options})
add_dependencies(DetouristPublishedApiTests DetouristCollector)
add_test(NAME published_apis COMMAND DetouristPublishedApiTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(published_apis PROPERTIES TIMEOUT 180 LABELS "coverage;com;catalog")
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    add_test(NAME published_apis_instructions COMMAND DetouristPublishedApiTests
        $<TARGET_FILE:DetouristCollector> --instructions)
    set_tests_properties(published_apis_instructions PROPERTIES TIMEOUT 180 LABELS "coverage;com;catalog")
endif()
