# Compile one scenario per executable so ABI settings and process isolation remain independent.
function(detourist_test_target target)
    cmake_parse_arguments(PARSE_ARGV 1 test "NO_RTTI" "" "")
    add_executable(${target} ${test_UNPARSED_ARGUMENTS})
    if(test_NO_RTTI)
        target_compile_options(${target} PRIVATE /GR- /Ob0)
    endif()
    target_compile_definitions(${target} PRIVATE "DETOURIST_TEST_${target}")
endfunction()

function(detourist_support support)
    add_library(${support} STATIC Test/TestSupport.cpp)
    target_include_directories(${support} PUBLIC Test Source/common "${sqlite_SOURCE_DIR}")
    target_link_libraries(${support} PUBLIC DetouristSqlite nlohmann_json::nlohmann_json)
    target_compile_definitions(${support} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_compile_options(${support} PRIVATE ${detourist_cxx_options})
endfunction()
detourist_support(detourist_test_support)

function(detourist_capture_test target)
    detourist_test_target(${target} ${ARGN})
    add_dependencies(${target} DetouristCollector)
    add_dependencies(DetouristNativeTests ${target})
    set_property(GLOBAL APPEND PROPERTY DETOURIST_CAPTURE_TESTS ${target})
endfunction()

# Test cases are selected by decoding rules and observable failure modes.
detourist_test_target(DetouristTestTarget Test/NativeTargets.cpp)
target_link_libraries(DetouristTestTarget PRIVATE detourist_common advapi32 psapi)

detourist_test_target(DetouristCaptureTests Test/CaptureTests.cpp)
target_link_libraries(DetouristCaptureTests PRIVATE detourist_test_support detourist_capture detours advapi32)
add_dependencies(DetouristCaptureTests DetouristCollector DetouristTestTarget)
detourist_add_test(capture_image_signing 60 SERIAL INSTRUCTIONS DetouristCaptureTests --image-signing)
detourist_add_test(capture_thread_discovery 90 SERIAL DetouristCaptureTests --thread-discovery)
detourist_add_test(capture_storage 60 DetouristCaptureTests --storage)
detourist_add_test(capture_durations 120 SERIAL INSTRUCTIONS DetouristCaptureTests --durations)

detourist_python_test(collector 120 SessionTests.py collector $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristTestTarget>)
foreach(scenario breakpoints views)
    detourist_python_test(collector_failures_${scenario} 120 SessionTests.py failures ${scenario}
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristTestTarget>)
endforeach()
foreach(scenario queries snapshots pressure)
    detourist_python_test(collector_concurrency_${scenario} 120 ConcurrencyTests.py SERIAL ${scenario}
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristTestTarget>)
endforeach()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # The x86 captures need longer under WOW64 and the main fixture must run alone.
    set_tests_properties(collector collector_concurrency_queries collector_concurrency_snapshots
        collector_concurrency_pressure PROPERTIES TIMEOUT 150)
    detourist_add_test(capture 150 SERIAL DetouristCaptureTests)
    include(Test/X86Tests.cmake)
    return()
endif()
detourist_add_test(capture 120 DetouristCaptureTests)
add_custom_target(DetouristNativeTests)
detourist_support(detourist_test_support_dll)
set_target_properties(detourist_test_support_dll PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    detourist_capture_test(DetouristBreakpointMetadataTests Test/RuntimeTests.cpp)
endif()

detourist_python_test(noise_filters 90 NoiseFilterTests.py INSTRUCTIONS SERIAL $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristTestTarget>)
detourist_python_test(capture_diagnostics 60 CaptureDiagnosticsTests.py SERIAL $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristTestTarget>)
detourist_python_test(child_lifecycle 90 ChildLifecycleTests.py INSTRUCTIONS SERIAL $<TARGET_FILE:DetouristCollector>
    $<TARGET_FILE:DetouristTestTarget>)
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    detourist_python_test(instruction_concurrency 300 InstructionConcurrencyTests.py SERIAL
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristTestTarget>)
endif()

detourist_python_test(console_launch 120 SessionTests.py INSTRUCTIONS SERIAL console $<TARGET_FILE:DetouristCollector>)
set(detourist_desktop_arguments)
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    set(detourist_desktop_arguments --com-inspection)
endif()
detourist_add_test(desktop 300 SERIAL DESKTOP "${DETOURIST_DOTNET}" "${detourist_desktop_test_assembly}"
    ${detourist_desktop_arguments})
detourist_add_test(desktop_rtm_fields 30 DESKTOP "${DETOURIST_DOTNET}" "${detourist_desktop_test_assembly}"
    --rtm-fields)
detourist_add_test(desktop_view_concurrency 120 SERIAL DESKTOP "${DETOURIST_DOTNET}"
    "${detourist_desktop_test_assembly}" --view-concurrency)
detourist_add_test(desktop_catalog 180 SERIAL DESKTOP "${DETOURIST_DOTNET}" "${detourist_desktop_test_assembly}"
    --catalog-editing)
detourist_add_test(desktop_collector_failures 120 SERIAL DESKTOP "${DETOURIST_DOTNET}"
    "${detourist_desktop_test_assembly}" --collector-failures)
detourist_add_test(desktop_window_spy 120 SERIAL DESKTOP "${DETOURIST_DOTNET}" "${detourist_desktop_test_assembly}"
    --window-spy)
detourist_test_target(DetouristComTarget Test/ComTarget.cpp)
target_link_libraries(DetouristComTarget PRIVATE detourist_common ole32 oleaut32 runtimeobject uuid
    d2d1 d3d11 d3d12 dwrite dxgi)
detourist_python_test(com 90 ComTests.py interfaces $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristComTarget>)

detourist_capture_test(DetouristProviderComTests Test/ProviderTests.cpp)
target_link_libraries(DetouristProviderComTests PRIVATE ole32 uuid mfuuid d3d11)
target_compile_options(DetouristProviderComTests PRIVATE ${detourist_cxx_options})
detourist_capture_test(DetouristSpiTests Test/SpiTests.cpp)
target_link_libraries(DetouristSpiTests PRIVATE ws2_32)
target_compile_options(DetouristSpiTests PRIVATE ${detourist_cxx_options})
detourist_add_test(provider_spi 90 SERIAL INSTRUCTIONS DetouristSpiTests $<TARGET_FILE:DetouristCollector>)
detourist_capture_test(DetouristCertificateLookupTests Test/CertificateLookupTests.cpp)
target_link_libraries(DetouristCertificateLookupTests PRIVATE crypt32)
target_compile_options(DetouristCertificateLookupTests PRIVATE ${detourist_cxx_options})
detourist_add_test(certificate_lookup 90 SERIAL INSTRUCTIONS DetouristCertificateLookupTests
    $<TARGET_FILE:DetouristCollector>)
set(detourist_d3dx_include "${CMAKE_SOURCE_DIR}/.dependencies/d3dx-headers/package/build/native/include")
set(detourist_com_providers "combase|combase.dll" "capture|mfcaptureengine.dll" "wab|wab32.dll"
    "compute|d3dcsx_42.dll" "compute|d3dcsx_43.dll")
if(EXISTS "${detourist_d3dx_include}/D3DX11.h")
    target_include_directories(DetouristProviderComTests SYSTEM PRIVATE "${detourist_d3dx_include}")
    target_compile_definitions(DetouristProviderComTests PRIVATE DETOURIST_TEST_D3DX)
    list(APPEND detourist_com_providers "d3dx|d3dx11_42.dll" "d3dx|d3dx11_43.dll")
endif()
foreach(provider ${detourist_com_providers})
    string(REPLACE "|" ";" fields "${provider}")
    list(GET fields 0 mode)
    list(GET fields 1 library)
    string(REPLACE ".dll" "" test_name "${library}")
    detourist_add_test("provider_com_${test_name}" 180 DetouristProviderComTests $<TARGET_FILE:DetouristCollector>
        "${mode}" "${library}")
    set_tests_properties("provider_com_${test_name}" PROPERTIES SKIP_RETURN_CODE 77 LABELS "com;providers")
endforeach()

detourist_capture_test(DetouristShellSdkTests Test/ProviderTests.cpp)
target_link_libraries(DetouristShellSdkTests PRIVATE shell32 ole32 uuid)
target_compile_options(DetouristShellSdkTests PRIVATE ${detourist_cxx_options})
detourist_add_test(shell_items_sdk_fixed 180 DetouristShellSdkTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(shell_items_sdk_fixed PROPERTIES LABELS "com;providers")

detourist_capture_test(DetouristPropertyStoreTests Test/PropertyTests.cpp)
target_link_libraries(DetouristPropertyStoreTests PRIVATE propsys ole32 oleaut32 uuid)
target_compile_options(DetouristPropertyStoreTests PRIVATE ${detourist_cxx_options})
detourist_add_test(property_stores_fixed 180 INSPECTOR DetouristPropertyStoreTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(property_stores_fixed PROPERTIES LABELS "com;providers;values")
detourist_capture_test(DetouristPropertyGraphTests NO_RTTI Test/PropertyTests.cpp)
target_link_libraries(DetouristPropertyGraphTests PRIVATE propsys ole32 oleaut32 uuid)
target_compile_options(DetouristPropertyGraphTests PRIVATE ${detourist_warnings})
target_compile_definitions(DetouristPropertyGraphTests PRIVATE NOMINMAX)
detourist_add_test(property_graphs_fixed 360 INSPECTOR DetouristPropertyGraphTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(property_graphs_fixed PROPERTIES LABELS "com;providers;values")
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    detourist_add_test(property_graphs 360 INSPECTOR DetouristPropertyGraphTests $<TARGET_FILE:DetouristCollector>
        --instructions)
    set_tests_properties(property_graphs PROPERTIES LABELS "com;providers;values")
    detourist_add_test(property_stores 180 INSPECTOR DetouristPropertyStoreTests $<TARGET_FILE:DetouristCollector>
        --instructions)
    set_tests_properties(property_stores PROPERTIES LABELS "com;providers;values")
endif()

detourist_capture_test(DetouristWin32Tests Test/Win32Tests.cpp)
target_link_libraries(DetouristWin32Tests PRIVATE detourist_common advapi32 user32 gdi32 ws2_32)
detourist_add_test(win32 90 DetouristWin32Tests $<TARGET_FILE:DetouristCollector>)

detourist_python_test(categories 120 SessionTests.py categories $<TARGET_FILE:DetouristCollector> --win32
    $<TARGET_FILE:DetouristWin32Tests> --child $<TARGET_FILE:DetouristTestTarget> --com
    $<TARGET_FILE:DetouristComTarget>)
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    # Typed vtables and runtime formats require instruction capture.

    get_filename_component(cx_tools "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(cx_tools "${cx_tools}/../../.." ABSOLUTE)
    set(cx_platform_metadata "${cx_tools}/lib/x86/store/references")
    string(CONCAT cx_windows_metadata "C:/Program Files (x86)/Windows Kits/10/UnionMetadata/"
        "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION_MAXIMUM}")
    if(EXISTS "${cx_platform_metadata}/platform.winmd" AND EXISTS "${cx_windows_metadata}/Windows.winmd")

        detourist_capture_test(DetouristCxxCxTests Test/RuntimeTests.cpp)
        add_library(detourist_cxxcx_workload OBJECT Test/CxxCxWorkload.cpp)
        target_sources(DetouristCxxCxTests PRIVATE $<TARGET_OBJECTS:detourist_cxxcx_workload>)
        set_target_properties(DetouristCxxCxTests PROPERTIES MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        # Visual Studio archives object targets, but the executable consumes their objects directly.
        set_target_properties(detourist_cxxcx_workload PROPERTIES CXX_STANDARD 14
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
            STATIC_LIBRARY_OPTIONS /IGNORE:4264)
        target_compile_options(detourist_cxxcx_workload PRIVATE /ZW
            "/AI${cx_platform_metadata}" "/AI${cx_windows_metadata}")
        target_link_libraries(DetouristCxxCxTests PRIVATE vccorlib)
        detourist_add_test(cxxcx_contracts 120 DetouristCxxCxTests $<TARGET_FILE:DetouristCollector>)
    endif()

    detourist_capture_test(DetouristAviSaveTests Test/NativeContracts.cpp)
    target_link_libraries(DetouristAviSaveTests PRIVATE detourist_common vfw32 nlohmann_json::nlohmann_json)
    detourist_add_test(avi_save_contracts 300 INSPECTOR DetouristAviSaveTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristAuthzAuditTests Test/AuthzTests.cpp)
    target_link_libraries(DetouristAuthzAuditTests PRIVATE detourist_common detourist_arguments authz
        nlohmann_json::nlohmann_json)
    detourist_add_test(authz_audit_contracts 300 INSPECTOR DetouristAuthzAuditTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristAuthzAccessTests Test/AuthzTests.cpp)
    target_link_libraries(DetouristAuthzAccessTests PRIVATE detourist_common authz advapi32
        nlohmann_json::nlohmann_json)
    detourist_add_test(authz_access_contracts 300 INSPECTOR DetouristAuthzAccessTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristBerVariadicTests Test/LdapTests.cpp)
    target_link_libraries(DetouristBerVariadicTests PRIVATE wldap32)
    detourist_add_test(ber_variadic_capture 120 DESKTOP DetouristBerVariadicTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristFormatVariadicTests Test/FormatTests.cpp)
    target_link_libraries(DetouristFormatVariadicTests PRIVATE user32 shlwapi)
    detourist_add_test(format_variadic_prefixes 90 DetouristFormatVariadicTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristShellMessageTests Test/ShellMessageTests.cpp Test/ShellMessageTarget.rc)
    target_link_libraries(DetouristShellMessageTests PRIVATE user32 oleacc ole32 oleaut32
        nlohmann_json::nlohmann_json)
    detourist_add_test(shell_message_formats 1500 DESKTOP DetouristShellMessageTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")
    detourist_capture_test(DetouristShellMessageUtf8Tests Test/ShellMessageTests.cpp Test/ShellMessageTarget.rc
        Test/ShellMessageUtf8.manifest)
    target_link_libraries(DetouristShellMessageUtf8Tests PRIVATE user32 oleacc ole32 oleaut32
        nlohmann_json::nlohmann_json)
    detourist_add_test(shell_message_utf8_formats 480 DESKTOP DetouristShellMessageUtf8Tests
        $<TARGET_FILE:DetouristCollector> "${detourist_desktop_test_assembly}" --utf8)
    foreach(language English French)
        add_library(DetouristShellResources${language} SHARED Test/ShellMessageResources.rc)
        set_target_properties(DetouristShellResources${language} PROPERTIES LINKER_LANGUAGE CXX)
        string(TOUPPER "${language}" definition)
        target_compile_definitions(DetouristShellResources${language} PRIVATE SHELL_RESOURCE_${definition})
        target_link_options(DetouristShellResources${language} PRIVATE
            /NOENTRY /NODEFAULTLIB /MANIFEST:NO /INCREMENTAL:NO)
    endforeach()
    find_program(detourist_muirct muirct PATHS
        "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64" REQUIRED)
    detourist_add_test(shell_message_resources 1500 DESKTOP DetouristShellMessageTests $<TARGET_FILE:DetouristCollector>
        --resources $<TARGET_FILE:DetouristShellMessageUtf8Tests> "${detourist_desktop_test_assembly}"
        $<TARGET_FILE:DetouristShellResourcesEnglish> $<TARGET_FILE:DetouristShellResourcesFrench> "${detourist_muirct}"
        "${CMAKE_SOURCE_DIR}/Test/ShellMessageResources.rcconfig")
    detourist_capture_test(DetouristPromptUserTests Test/ShellTests.cpp)
    target_link_libraries(DetouristPromptUserTests PRIVATE user32 nlohmann_json::nlohmann_json)
    detourist_add_test(prompt_user_inserts 600 DESKTOP DetouristPromptUserTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")
    detourist_capture_test(DetouristWindowCompositionTests Test/ShellTests.cpp)
    target_link_libraries(DetouristWindowCompositionTests PRIVATE user32 dwmapi nlohmann_json::nlohmann_json)
    detourist_add_test(window_composition_contracts 600 DESKTOP DetouristWindowCompositionTests
        $<TARGET_FILE:DetouristCollector> "${detourist_desktop_test_assembly}")
    detourist_capture_test(DetouristTraceLoggingTests Test/NativeContracts.cpp)
    target_link_libraries(DetouristTraceLoggingTests PRIVATE advapi32)
    detourist_add_test(trace_logging_events 240 DESKTOP DetouristTraceLoggingTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristLdapModTests Test/LdapTests.cpp)
    detourist_add_test(ldap_mod_buffers 180 DESKTOP DetouristLdapModTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristUcrtVaListTests Test/FormatTests.cpp)
    detourist_add_test(ucrt_va_list_capture 180 DESKTOP DetouristUcrtVaListTests $<TARGET_FILE:DetouristCollector>
        "${CMAKE_BINARY_DIR}/ucrt-inspection-$<CONFIG>.json" "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristLegacyFormatListTests Test/FormatTests.cpp)
    target_link_libraries(DetouristLegacyFormatListTests PRIVATE nlohmann_json::nlohmann_json)
    detourist_add_test(legacy_format_lists 360 DESKTOP DetouristLegacyFormatListTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristCrtCountOutputTests Test/FormatOutputTests.cpp)
    detourist_add_test(crt_count_outputs 180 DESKTOP DetouristCrtCountOutputTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristCrtCountedStringTests Test/FormatOutputTests.cpp)
    detourist_add_test(crt_counted_strings 180 DESKTOP DetouristCrtCountedStringTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristNtdllFormatTests Test/FormatOutputTests.cpp)
    detourist_add_test(ntdll_format_contracts 180 DESKTOP DetouristNtdllFormatTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristLocaleFormatTests Test/FormatOutputTests.cpp)
    detourist_add_test(locale_format_precision 180 DESKTOP DetouristLocaleFormatTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristScanFormatTests Test/ScanFormatTests.cpp)
    detourist_add_test(scan_format_destinations 300 DESKTOP DetouristScanFormatTests $<TARGET_FILE:DetouristCollector>
        "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristRunAsTests Test/ShellTests.cpp)
    target_link_libraries(DetouristRunAsTests PRIVATE detourist_common ole32 user32 nlohmann_json::nlohmann_json)
    detourist_add_test(shell_run_as_contract 240 DetouristRunAsTests $<TARGET_FILE:DetouristCollector> --capture)

    detourist_capture_test(DetouristPositionalRecordTests Test/NativeContracts.cpp)
    detourist_add_test(positional_counted_records 180 DESKTOP DetouristPositionalRecordTests
        $<TARGET_FILE:DetouristCollector> "${detourist_desktop_test_assembly}")

    detourist_capture_test(DetouristNoRttiComTests NO_RTTI Test/ComDispatchTests.cpp)
    target_compile_definitions(DetouristNoRttiComTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristNoRttiComTests PRIVATE uuid)
    detourist_add_test(com_no_rtti 90 DetouristNoRttiComTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristContextComTests NO_RTTI Test/ComDispatchTests.cpp)
    target_compile_definitions(DetouristContextComTests PRIVATE NOMINMAX USE_COM_CONTEXT_DEF)
    target_link_libraries(DetouristContextComTests PRIVATE ole32 uuid)
    detourist_add_test(com_context_contracts 90 DetouristContextComTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristAllocatedVariantTests NO_RTTI Test/ComValueTests.cpp)
    target_compile_definitions(DetouristAllocatedVariantTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristAllocatedVariantTests PRIVATE ole32 oleaut32 uuid)
    detourist_add_test(com_allocated_variants 90 DetouristAllocatedVariantTests $<TARGET_FILE:DetouristCollector>)
    detourist_python_test(com_variant_discovery 90 ComTests.py variant_discovery $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAllocatedVariantTests>)

    detourist_capture_test(DetouristVariantBufferTests NO_RTTI Test/ComValueTests.cpp)
    target_compile_definitions(DetouristVariantBufferTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristVariantBufferTests PRIVATE ole32 oleaut32 uuid)
    detourist_add_test(com_variant_buffers 120 DetouristVariantBufferTests $<TARGET_FILE:DetouristCollector>)

    detourist_test_target(DetouristAutomationTarget NO_RTTI Test/AutomationTarget.cpp)
    target_compile_definitions(DetouristAutomationTarget PRIVATE NOMINMAX)
    target_link_libraries(DetouristAutomationTarget PRIVATE ole32 oleaut32 uuid)
    detourist_python_test(automation_interfaces 180 AutomationTests.py interfaces $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(automation_array_values 120 AutomationTests.py arrays $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(automation_array_strings 120 AutomationTests.py strings $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(automation_enumeration 120 AutomationTests.py enumeration $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(automation_records 180 AutomationTests.py records $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(com_base_interface_tails 90 ComTests.py base_tails $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)
    detourist_python_test(com_attach_lifecycle 120 ComTests.py attach $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAutomationTarget>)

    detourist_capture_test(DetouristComArrayTests NO_RTTI Test/ComArrayTests.cpp)
    target_compile_definitions(DetouristComArrayTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristComArrayTests PRIVATE ole32 uuid)
    detourist_add_test(com_interface_arrays 300 DetouristComArrayTests $<TARGET_FILE:DetouristCollector>)
    detourist_add_test(com_allocated_interface_arrays 90 DetouristComArrayTests $<TARGET_FILE:DetouristCollector>
        --allocated-only)
    set_tests_properties(com_allocated_interface_arrays PROPERTIES LABELS "coverage;catalog;abi;com")

    detourist_capture_test(DetouristComRpcTests NO_RTTI Test/ComRpcTests.cpp)
    target_compile_definitions(DetouristComRpcTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristComRpcTests PRIVATE ole32 oleaut32 uuid)
    detourist_add_test(com_rpc_arrays 600 DetouristComRpcTests $<TARGET_FILE:DetouristCollector>)

    detourist_test_target(DetouristDetachCallbackTarget Test/NativeTargets.cpp)
    target_compile_definitions(DetouristDetachCallbackTarget PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(DetouristDetachCallbackTarget PRIVATE user32)
    detourist_python_test(detach_callbacks 150 SessionTests.py detach $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristDetachCallbackTarget>)

    detourist_capture_test(DetouristPropertyVariantTests NO_RTTI Test/ComValueTests.cpp)
    target_compile_options(DetouristPropertyVariantTests PRIVATE /W4 /WX /utf-8)
    target_compile_definitions(DetouristPropertyVariantTests PRIVATE NOMINMAX)
    target_link_libraries(DetouristPropertyVariantTests PRIVATE ole32 oleaut32 uuid)
    detourist_add_test(com_property_variants 600 DetouristPropertyVariantTests $<TARGET_FILE:DetouristCollector>)
    detourist_python_test(com_property_vectors 210 ComTests.py INSPECTOR property_vectors
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristPropertyVariantTests>)

    detourist_capture_test(DetouristGuardedComTests NO_RTTI Test/ComDispatchTests.cpp)
    target_compile_definitions(DetouristGuardedComTests PRIVATE NOMINMAX DETOURIST_TEST_GUARDED)
    target_compile_options(DetouristGuardedComTests PRIVATE /guard:cf)
    target_link_options(DetouristGuardedComTests PRIVATE /guard:cf /DYNAMICBASE)
    target_link_libraries(DetouristGuardedComTests PRIVATE uuid)
    detourist_add_test(com_guarded_dispatch 90 DetouristGuardedComTests $<TARGET_FILE:DetouristCollector>)
    set(DETOURIST_XFG_TEST_TOOLSET "" CACHE STRING "MSVC toolset version that emits XFG dispatch calls")
    if(DETOURIST_XFG_TEST_TOOLSET AND CMAKE_GENERATOR MATCHES "^Visual Studio")

        detourist_capture_test(DetouristXfgComTests NO_RTTI Test/ComDispatchTests.cpp)
        set_target_properties(DetouristXfgComTests PROPERTIES VS_PLATFORM_TOOLSET v143
            VS_GLOBAL_VCToolsVersion "${DETOURIST_XFG_TEST_TOOLSET}")
        target_compile_definitions(DetouristXfgComTests PRIVATE NOMINMAX
            DETOURIST_TEST_GUARDED DETOURIST_TEST_XFG)
        target_compile_options(DetouristXfgComTests PRIVATE /guard:xfg /wd5252)
        target_link_options(DetouristXfgComTests PRIVATE /guard:xfg /DYNAMICBASE)
        target_link_libraries(DetouristXfgComTests PRIVATE uuid)
        detourist_add_test(com_xfg_dispatch 90 DetouristXfgComTests $<TARGET_FILE:DetouristCollector> --xfg)
    endif()
    detourist_add_test(win32_instructions 90 DetouristWin32Tests $<TARGET_FILE:DetouristCollector> --instructions)

    detourist_capture_test(DetouristCppRuntimeTests Test/RuntimeTests.cpp)
    set_target_properties(DetouristCppRuntimeTests PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    detourist_add_test(cpp_runtime_exports 120 DetouristCppRuntimeTests $<TARGET_FILE:DetouristCollector>)
    detourist_add_test(cpp_runtime_exports_native 120 DetouristCppRuntimeTests $<TARGET_FILE:DetouristCollector>
        --native)
    detourist_test_target(DetouristInstructionTarget Test/NativeTargets.cpp)
    target_link_libraries(DetouristInstructionTarget PRIVATE detourist_common)
    detourist_python_test(instructions 160 SessionTests.py instructions $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristInstructionTarget> $<TARGET_FILE:DetouristTestTarget>)

    detourist_capture_test(DetouristStackProbeTests Test/NativeContracts.cpp Test/StackProbeCall.asm)
    detourist_add_test(stack_probe_contracts 120 DetouristStackProbeTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristDavComplianceTests Test/NativeContracts.cpp)
    detourist_add_test(dav_compliance_contracts 120 DetouristDavComplianceTests $<TARGET_FILE:DetouristCollector>)

    detourist_capture_test(DetouristCscSearchTests Test/NativeContracts.cpp)
    detourist_add_test(csc_search_contracts 120 DetouristCscSearchTests $<TARGET_FILE:DetouristCollector>)
    detourist_python_test(com_instructions 180 ComTests.py SERIAL interfaces $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristComTarget> --instructions)
    detourist_capture_test(DetouristLdapControlTests Test/LdapTests.cpp)
    target_link_libraries(DetouristLdapControlTests PRIVATE wldap32)
    detourist_add_test(ldap_control_buffers 180 DetouristLdapControlTests $<TARGET_FILE:DetouristCollector>)

    detourist_test_target(DetouristAutomationCaptureTests Test/RuntimeTests.cpp)
    target_link_libraries(DetouristAutomationCaptureTests PRIVATE detourist_test_support detourist_common)
    detourist_add_test(automation_capture_buffers 15 DetouristAutomationCaptureTests)
    add_test(NAME com_parameterized COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/Test/ComTests.py parameterized
        $<TARGET_FILE:DetouristCollector> $<TARGET_FILE:DetouristComTarget>)
    detourist_python_test(com_structures 100 ComTests.py winrt_structures $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristComTarget>)

    detourist_test_target(DetouristAdsiTarget Test/AdsiTarget.cpp)
    target_compile_options(DetouristAdsiTarget PRIVATE /GR /Ob0)
    target_compile_definitions(DetouristAdsiTarget PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(DetouristAdsiTarget PRIVATE oleaut32)
    detourist_python_test(com_adsi_structures 90 ComTests.py adsi_structures $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAdsiTarget>)
    detourist_python_test(com_typed_variant_arrays 90 ComTests.py adsi_arrays $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristAdsiTarget>)
    detourist_add_test(breakpoint_metadata 90 DetouristBreakpointMetadataTests $<TARGET_FILE:DetouristCollector>
        $<TARGET_FILE:DetouristComTarget>)

    detourist_capture_test(DetouristSyscallTests Test/SyscallTests.cpp)
    target_link_libraries(DetouristSyscallTests PRIVATE detourist_common user32)
    detourist_add_test(syscalls 600 DetouristSyscallTests $<TARGET_FILE:DetouristCollector>)
    detourist_python_test(categories_instructions 240 SessionTests.py categories $<TARGET_FILE:DetouristCollector>
        --instructions --win32 $<TARGET_FILE:DetouristWin32Tests> --child $<TARGET_FILE:DetouristTestTarget> --com
        $<TARGET_FILE:DetouristComTarget> --syscalls $<TARGET_FILE:DetouristSyscallTests>)
endif()
if(DETOURIST_BUILD_PROFILER)
    include(Test/ManagedTests.cmake)
endif()

# Match each controller's support library to its workload's CRT settings.
if(DETOURIST_XFG_TEST_TOOLSET AND CMAKE_GENERATOR MATCHES "^Visual Studio")
    detourist_support(detourist_test_support_xfg)
    target_compile_options(detourist_test_support_xfg PRIVATE /guard:xfg /wd5252)
    set_target_properties(detourist_test_support_xfg PROPERTIES VS_PLATFORM_TOOLSET v143
        VS_GLOBAL_VCToolsVersion "${DETOURIST_XFG_TEST_TOOLSET}")
endif()
get_property(capture_tests GLOBAL PROPERTY DETOURIST_CAPTURE_TESTS)
foreach(test IN LISTS capture_tests)
    get_target_property(runtime ${test} MSVC_RUNTIME_LIBRARY)
    get_target_property(toolset ${test} VS_GLOBAL_VCToolsVersion)
    if(toolset AND TARGET detourist_test_support_xfg)
        target_link_libraries(${test} PRIVATE detourist_test_support_xfg)
    elseif(runtime MATCHES "DLL")
        target_link_libraries(${test} PRIVATE detourist_test_support_dll)
    else()
        target_link_libraries(${test} PRIVATE detourist_test_support)
    endif()
    target_compile_options(${test} PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>)
    get_target_property(options ${test} COMPILE_OPTIONS)
    if(NOT "/EHa" IN_LIST options)
        target_compile_options(${test} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/EHsc>)
    endif()
endforeach()

# Native controller fixture dependencies.
if(TARGET DetouristBreakpointMetadataTests AND TARGET DetouristComTarget)
    add_dependencies(DetouristBreakpointMetadataTests DetouristComTarget)
endif()
foreach(fixture DetouristShellMessageUtf8Tests DetouristShellResourcesEnglish DetouristShellResourcesFrench)
    if(TARGET DetouristShellMessageTests AND TARGET ${fixture})
        add_dependencies(DetouristShellMessageTests ${fixture})
    endif()
endforeach()
