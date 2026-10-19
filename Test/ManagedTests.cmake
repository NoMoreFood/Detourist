if(BUILD_TESTING AND DETOURIST_BUILD_PROFILER)
    find_program(DETOURIST_DOTNET dotnet REQUIRED)
    set(managed_output "${CMAKE_BINARY_DIR}/managed/")
    set(managed_runtime_suffix "")
    set(managed_arguments)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(managed_runtime_suffix /win-x86)
        list(APPEND managed_arguments -p:PlatformTarget=x86 -p:RuntimeIdentifier=win-x86)
    endif()
    set(managed_core "${managed_output}Release/net10.0${managed_runtime_suffix}/DetouristManagedTarget.exe")
    set(managed_framework "${managed_output}Release/net48${managed_runtime_suffix}/DetouristManagedTarget.exe")
    set(DETOURIST_LEGACY_CLR_DIRECTORY "" CACHE PATH "CLR 2 framework directory for legacy capture tests")
    set(managed_targets "${managed_core}" "${managed_framework}")
    set(managed_runtime_commands)
    if(EXISTS "${DETOURIST_LEGACY_CLR_DIRECTORY}/mscorwks.dll")
        set(managed_legacy "${managed_output}Release/net35${managed_runtime_suffix}/DetouristManagedTarget.exe")
        list(APPEND managed_targets "${managed_legacy}")
        list(APPEND managed_arguments "-p:LegacyClrTests=true")
        list(APPEND managed_runtime_commands COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${DETOURIST_LEGACY_CLR_DIRECTORY}/System.Xml.dll"
            "${managed_output}Release/net35${managed_runtime_suffix}/System.Xml.dll")
        add_executable(DetouristManagedHost Test/ManagedHostTarget.cpp)
        target_include_directories(DetouristManagedHost SYSTEM PRIVATE "${DETOURIST_CLR_INCLUDE}")
        target_link_libraries(DetouristManagedHost PRIVATE detourist_common ${DETOURIST_CLR_GUIDS} ole32)
        target_compile_options(DetouristManagedHost PRIVATE ${detourist_cxx_options})
        detourist_python_test(managed_legacy 140 ManagedTests.py launch $<TARGET_FILE:DetouristCollector>
            "${managed_legacy}" --host $<TARGET_FILE:DetouristManagedHost> --runtime
            "${DETOURIST_LEGACY_CLR_DIRECTORY}")
        if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
            detourist_python_test(managed_legacy_instructions 140 ManagedTests.py launch
                $<TARGET_FILE:DetouristCollector> "${managed_legacy}" --host $<TARGET_FILE:DetouristManagedHost>
                --runtime "${DETOURIST_LEGACY_CLR_DIRECTORY}" --instructions --strict-native-interop)
        endif()
        if(DETOURIST_BUILD_MANAGED_DEBUGGER)
            detourist_python_test(managed_legacy_attach 180 ManagedTests.py attach $<TARGET_FILE:DetouristCollector>
                "${managed_legacy}" --debugger --host $<TARGET_FILE:DetouristManagedHost> --runtime
                "${DETOURIST_LEGACY_CLR_DIRECTORY}")
        endif()
    endif()
    add_custom_command(OUTPUT ${managed_targets}
        COMMAND "${DETOURIST_DOTNET}" build "${CMAKE_SOURCE_DIR}/Test/ManagedTarget/ManagedTarget.csproj"
            --configuration Release --nologo "-p:BaseOutputPath=${managed_output}"
            "-p:DetouristBuildDirectory=${CMAKE_BINARY_DIR}" ${managed_arguments}
        DEPENDS "${CMAKE_SOURCE_DIR}/Test/ManagedTarget/ManagedTarget.csproj"
            "${CMAKE_SOURCE_DIR}/Test/ManagedTarget/Program.cs"
            "${CMAKE_SOURCE_DIR}/Test/ManagedTarget/ImageCapture.cs" "${CMAKE_SOURCE_DIR}/Directory.Build.props"
        VERBATIM)
    add_custom_target(DetouristManagedTarget ALL DEPENDS ${managed_targets} ${managed_runtime_commands} VERBATIM)
    add_dependencies(DetouristManagedTarget DetouristProfiler DetouristCollector)
    detourist_python_test(managed_core 140 ManagedTests.py launch $<TARGET_FILE:DetouristCollector> "${managed_core}")
    detourist_python_test(managed_framework 140 ManagedTests.py launch $<TARGET_FILE:DetouristCollector>
        "${managed_framework}")
    detourist_python_test(managed_com_images 120 ManagedImageTests.py $<TARGET_FILE:DetouristCollector>
        "${managed_framework}")
    set(layout_runtimes core framework)
    if(DEFINED managed_legacy)
        list(APPEND layout_runtimes legacy)
    endif()
    foreach(runtime IN LISTS layout_runtimes)
        set(layout_arguments)
        if(runtime STREQUAL "legacy")
            list(APPEND layout_arguments --host $<TARGET_FILE:DetouristManagedHost>
                --runtime "${DETOURIST_LEGACY_CLR_DIRECTORY}")
        endif()
        detourist_python_test(managed_layout_${runtime} 240 ManagedValueTests.py INSPECTOR layouts
            $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" ${layout_arguments})
        detourist_python_test(managed_arrays_${runtime} 200 ManagedValueTests.py INSPECTOR arrays
            $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" ${layout_arguments})
        if(DETOURIST_BUILD_MANAGED_DEBUGGER AND NOT runtime STREQUAL "core")
            detourist_python_test(managed_arrays_${runtime}_attach 200 ManagedValueTests.py INSPECTOR arrays
                $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" ${layout_arguments} --debugger)
            if(runtime STREQUAL "legacy")
                detourist_python_test(managed_arrays_legacy_generic_attach 200 ManagedValueTests.py INSPECTOR arrays
                    $<TARGET_FILE:DetouristCollector> "${managed_legacy}" ${layout_arguments} --debugger --generic)
            else()
                detourist_python_test(managed_arrays_framework_copy_attach 200 ManagedValueTests.py INSPECTOR arrays
                    $<TARGET_FILE:DetouristCollector> "${managed_framework}" --debugger --copy)
            endif()
        endif()
    endforeach()
    detourist_python_test(managed_arrays_core_attach 200 ManagedValueTests.py INSPECTOR arrays
        $<TARGET_FILE:DetouristCollector> "${managed_core}" --attach)
    detourist_python_test(managed_layout_core_attach 200 ManagedValueTests.py INSPECTOR attached_layouts
        $<TARGET_FILE:DetouristCollector> "${managed_core}")
    detourist_python_test(categories_managed 240 SessionTests.py categories $<TARGET_FILE:DetouristCollector> --managed
        "${managed_core}")
    detourist_python_test(managed_core_attach 180 ManagedTests.py INSPECTOR attach $<TARGET_FILE:DetouristCollector>
        "${managed_core}")
    detourist_python_test(managed_core_attach_filters 180 ManagedTests.py attach $<TARGET_FILE:DetouristCollector>
        "${managed_core}" --deferred)
    set(managed_framework_attach_arguments --requires-launch)
    if(DETOURIST_BUILD_MANAGED_DEBUGGER)
        set(managed_framework_attach_arguments --debugger)
    endif()
    detourist_python_test(managed_framework_attach 600 ManagedTests.py attach $<TARGET_FILE:DetouristCollector>
        "${managed_framework}" ${managed_framework_attach_arguments})
    if(DETOURIST_BUILD_MANAGED_DEBUGGER)
        detourist_python_test(managed_framework_capture_filter 120 ManagedTests.py debugger_filters
            $<TARGET_FILE:DetouristCollector> "${managed_framework}")
    endif()
    if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
        foreach(runtime IN ITEMS core framework)
            detourist_python_test(private_syscall_${runtime} 90 ManagedTests.py private_syscalls
                $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}")
            detourist_python_test(private_syscall_${runtime}_lifecycle 140 ManagedTests.py private_syscalls
                $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" --launch --lifecycle)
            if(CMAKE_SIZEOF_VOID_P EQUAL 4)
                detourist_python_test(private_syscall_${runtime}_legacy_gate 90 ManagedTests.py private_syscalls
                    $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" --launch --legacy-gate)
            endif()
            detourist_python_test(native_boundary_${runtime} 180 ManagedTests.py native_boundaries
                $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}")
            detourist_python_test(raw_native_${runtime} 90 ManagedTests.py raw_native $<TARGET_FILE:DetouristCollector>
                "${managed_${runtime}}")
            detourist_python_test(raw_native_${runtime}_breakpoints 90 ManagedTests.py raw_native
                $<TARGET_FILE:DetouristCollector> "${managed_${runtime}}" --breakpoints)
        endforeach()
        if(DEFINED managed_legacy)
            detourist_python_test(native_boundary_legacy 180 ManagedTests.py native_boundaries
                $<TARGET_FILE:DetouristCollector> "${managed_legacy}" --host $<TARGET_FILE:DetouristManagedHost>
                --runtime "${DETOURIST_LEGACY_CLR_DIRECTORY}")
            detourist_python_test(raw_native_legacy 90 ManagedTests.py raw_native $<TARGET_FILE:DetouristCollector>
                "${managed_legacy}" --host $<TARGET_FILE:DetouristManagedHost> --runtime
                "${DETOURIST_LEGACY_CLR_DIRECTORY}")
            detourist_python_test(raw_native_legacy_breakpoints 90 ManagedTests.py raw_native
                $<TARGET_FILE:DetouristCollector> "${managed_legacy}" --host $<TARGET_FILE:DetouristManagedHost>
                --runtime "${DETOURIST_LEGACY_CLR_DIRECTORY}" --breakpoints)
        endif()
        detourist_python_test(managed_core_attach_native_instructions 180 ManagedTests.py attach
            $<TARGET_FILE:DetouristCollector> "${managed_core}" --instructions --native-boundaries)
        detourist_python_test(managed_core_instructions 140 ManagedTests.py launch $<TARGET_FILE:DetouristCollector>
            "${managed_core}" --instructions --strict-native-interop --require-native-ntdll)
        detourist_python_test(managed_framework_instructions 140 ManagedTests.py launch
            $<TARGET_FILE:DetouristCollector> "${managed_framework}" --instructions --strict-native-interop)
    endif()
endif()
