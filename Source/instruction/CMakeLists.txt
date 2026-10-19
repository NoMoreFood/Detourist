option(DETOURIST_BUILD_INSTRUCTION_ENGINE "Build instruction capture for direct system calls"
    ${detourist_extended_default})
if(DETOURIST_BUILD_INSTRUCTION_ENGINE)
    math(EXPR detourist_dr_bits "${CMAKE_SIZEOF_VOID_P} * 8")
    set(detourist_dr_architecture X86_64)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(detourist_dr_architecture X86_32)
    endif()
    set(detourist_dr_version "11.3.0")
    set(detourist_dr_local "${CMAKE_SOURCE_DIR}/.dependencies/dynamorio/DynamoRIO-Windows-${detourist_dr_version}-1")
    if(EXISTS "${detourist_dr_local}/cmake/DynamoRIOConfig.cmake")
        set(detourist_dr_root "${detourist_dr_local}")
    else()
        FetchContent_Declare(dynamorio
            URL https://github.com/DynamoRIO/dynamorio/releases/download/release_${detourist_dr_version}-1/DynamoRIO-Windows-${detourist_dr_version}.zip
            URL_HASH SHA256=5516b8b4c929885dc4172e088ed11ea5db967f80ed739a3e7925fe2cdd798c6d
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
        FetchContent_MakeAvailable(dynamorio)
        set(detourist_dr_root "${dynamorio_SOURCE_DIR}")
    endif()
    # The client SDK and staged runtime must come from the same pinned release.
    set(DynamoRIO_DIR "${detourist_dr_root}/cmake" CACHE PATH "DynamoRIO SDK directory" FORCE)
    find_package(DynamoRIO ${detourist_dr_version} REQUIRED NO_DEFAULT_PATH)
    if(NOT DynamoRIO_VERSION VERSION_EQUAL detourist_dr_version)
        message(FATAL_ERROR "The DynamoRIO SDK must match the pinned runtime: ${detourist_dr_version}.")
    endif()

    # Build the pinned runtime with Windows native-return state restoration.
    find_package(Git REQUIRED)
    set(detourist_dr_patch "${CMAKE_SOURCE_DIR}/Build/Scripts/DynamoRIO.patch")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${detourist_dr_patch}")
    file(SHA256 "${detourist_dr_patch}" detourist_dr_patch_id)
    string(SUBSTRING "${detourist_dr_patch_id}" 0 12 detourist_dr_patch_id)
    FetchContent_Declare(dynamorio_source
        SOURCE_DIR "${FETCHCONTENT_BASE_DIR}/dr-${detourist_dr_patch_id}"
        URL https://codeload.github.com/DynamoRIO/dynamorio/zip/6847bb210bea0ca11d1bf47704383d6a075da490
        URL_HASH SHA256=68b644e897c9721e88595b594080cb59cd18f6ab996c62bbac3fb06b67c8a98d
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE SOURCE_SUBDIR detourist-runtime)
    FetchContent_MakeAvailable(dynamorio_source)
    # A reverse check also recognizes prepatched source overrides and preserves incremental build timestamps.
    set(detourist_dr_apply "${GIT_EXECUTABLE}" --git-dir=. --work-tree=. apply --whitespace=nowarn)
    execute_process(COMMAND ${detourist_dr_apply} --check --reverse --ignore-space-change "${detourist_dr_patch}"
        WORKING_DIRECTORY "${dynamorio_source_SOURCE_DIR}" RESULT_VARIABLE detourist_dr_unpatched ERROR_QUIET)
    if(detourist_dr_unpatched)
        execute_process(COMMAND ${detourist_dr_apply} "${detourist_dr_patch}"
            WORKING_DIRECTORY "${dynamorio_source_SOURCE_DIR}" COMMAND_ERROR_IS_FATAL ANY)
    endif()
    include(ExternalProject)
    set(detourist_dr_build "${CMAKE_BINARY_DIR}/dynamorio-runtime")
    set(detourist_dr_runtime "${detourist_dr_build}/lib${detourist_dr_bits}/release/dynamorio.dll")
    set(detourist_dr_configuration "${detourist_dr_build}/lib${detourist_dr_bits}/drconfiglib.dll")
    ExternalProject_Add(detourist_instruction_runtime
        SOURCE_DIR "${dynamorio_source_SOURCE_DIR}" BINARY_DIR "${detourist_dr_build}"
        DOWNLOAD_COMMAND "" UPDATE_COMMAND "" BUILD_ALWAYS TRUE
        CMAKE_ARGS --fresh -DCMAKE_POLICY_VERSION_MINIMUM=3.10
            -DDEBUG=OFF -DBUILD_CLIENTS=OFF -DBUILD_EXT=ON -DBUILD_TOOLS=OFF
            -DBUILD_DOCS=OFF -DBUILD_SAMPLES=OFF -DBUILD_TESTS=OFF -DDISABLE_WARNINGS=ON
            -DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config RelWithDebInfo
            --target dynamorio drmgr drwrap drconfiglib --parallel
        INSTALL_COMMAND "" BUILD_BYPRODUCTS "${detourist_dr_runtime}"
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drmgr.dll"
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drwrap.dll"
            "${detourist_dr_configuration}")
    # Reconfigure the runtime when the parent rediscovers the Visual Studio compiler.
    ExternalProject_Add_Step(detourist_instruction_runtime compiler
        DEPENDS "${CMAKE_PLATFORM_INFO_DIR}/CMakeCXXCompiler.cmake" DEPENDERS configure INDEPENDENT TRUE)
    add_library(DetouristInstructions SHARED Instructions.cpp InstructionChannel.cpp PublicCapture.cpp Exports.cpp ExportCalls.cpp
        ChildCapture.cpp ComCapture.cpp InstructionControl.cpp RuntimeCapture.cpp CatalogCapture.cpp CallbackCapture.cpp
        RuntimeFormatCapture.cpp RuntimeLocaleCapture.cpp RuntimeScanCapture.cpp RuntimeBerCapture.cpp
        StackProbe${detourist_assembly_suffix}.asm
        RuntimeMessageCapture.cpp ImportCapture.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/CaptureValues.cpp ${CMAKE_SOURCE_DIR}/Source/common/CatalogCaptureValues.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/AsyncIo.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/RpcCapture.cpp ${CMAKE_SOURCE_DIR}/Source/common/RpcFormats.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/RpcMarshal.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/ApiCategories.cpp
        ${CMAKE_SOURCE_DIR}/Source/common/CatalogView.cpp ${CMAKE_SOURCE_DIR}/Source/common/SdkCapture.cpp)
    target_include_directories(DetouristInstructions PRIVATE ${CMAKE_SOURCE_DIR}/Source/common
        ${CMAKE_BINARY_DIR}/generated
        ${CMAKE_SOURCE_DIR}/Source/agent)
    target_include_directories(DetouristInstructions SYSTEM PRIVATE "${phnt_SOURCE_DIR}")
    target_compile_definitions(DetouristInstructions PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 DETOURIST_INSTRUCTION_CLIENT)
    set(PREFERRED_BASE 0x180000000)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(PREFERRED_BASE 0x72000000)
    endif()
    configure_DynamoRIO_client(DetouristInstructions)
    unset(PREFERRED_BASE)
    use_DynamoRIO_extension(DetouristInstructions drmgr)
    use_DynamoRIO_extension(DetouristInstructions drwrap)
    add_dependencies(DetouristInstructions detourist_builtin_catalogs
        detourist_instruction_runtime)
    set_target_properties(DetouristInstructions PROPERTIES
        LINK_LIBRARIES "dynamorio;drmgr;drwrap;ntdll")
    target_compile_options(DetouristInstructions PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:/W4;/WX;/utf-8;/GS-;/GR-;/Zl;/bigobj>")
    # The private runtime client does not link a C++ exception runtime.
    get_target_property(detourist_dr_sources DetouristInstructions SOURCES)
    foreach(source IN LISTS detourist_dr_sources)
        get_source_file_property(flags "${source}" COMPILE_FLAGS)
        if(flags)
            string(REPLACE "/EHsc" "" flags "${flags}")
            set_source_files_properties("${source}" PROPERTIES COMPILE_FLAGS "${flags}")
        endif()
    endforeach()
    target_compile_options(DetouristInstructions PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/EHs-c->")
    target_link_options(DetouristInstructions PRIVATE /NODEFAULTLIB /NOENTRY /INCREMENTAL:NO)
    target_sources(detourist_capture PRIVATE ${CMAKE_SOURCE_DIR}/Source/capture/InstructionEngine.cpp)
    target_include_directories(detourist_capture SYSTEM PRIVATE "${detourist_dr_root}/include")
    target_compile_definitions(detourist_capture PRIVATE DETOURIST_INSTRUCTION_ENGINE WINDOWS
        ${detourist_dr_architecture})
    add_dependencies(DetouristCollector DetouristInstructions)
    foreach(extension drmgr drwrap)
        install(FILES "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/${extension}.dll" DESTINATION .)
    endforeach()

    # Keep the release runtime layout intact so the engine can resolve its own private libraries.
    set(detourist_dr_output "$<TARGET_FILE_DIR:DetouristInstructions>")
    file(GLOB detourist_dr_libraries "${detourist_dr_root}/lib${detourist_dr_bits}/release/*.dll")
    list(FILTER detourist_dr_libraries EXCLUDE REGEX "/dynamorio[.]dll$")
    file(GLOB detourist_dr_extensions "${detourist_dr_root}/ext/lib${detourist_dr_bits}/release/*.dll")
    add_custom_target(detourist_instruction_runtime_stage
        COMMAND ${CMAKE_COMMAND} -E make_directory "${detourist_dr_output}/instruction/bin${detourist_dr_bits}"
            "${detourist_dr_output}/instruction/lib${detourist_dr_bits}/release"
            "${detourist_dr_output}/instruction/ext/lib${detourist_dr_bits}/release"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${detourist_dr_libraries} "${detourist_dr_runtime}"
            "${detourist_dr_output}/instruction/lib${detourist_dr_bits}/release"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${detourist_dr_extensions}
            "${detourist_dr_output}/instruction/ext/lib${detourist_dr_bits}/release"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${detourist_dr_root}/bin${detourist_dr_bits}/drconfig.exe"
            "${detourist_dr_configuration}"
            "${detourist_dr_root}/bin${detourist_dr_bits}/drinjectlib.dll"
            "${detourist_dr_output}/instruction/bin${detourist_dr_bits}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drmgr.dll"
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drwrap.dll" "${detourist_dr_output}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drmgr.dll"
            "${detourist_dr_build}/ext/lib${detourist_dr_bits}/release/drwrap.dll"
            "${detourist_dr_output}/instruction/ext/lib${detourist_dr_bits}/release"
        DEPENDS detourist_instruction_runtime)
    add_dependencies(DetouristInstructions detourist_instruction_runtime_stage)
    if(BUILD_TESTING)
        add_executable(DetouristInstructionConfigTests "${CMAKE_SOURCE_DIR}/Test/InstructionConfigTests.cpp")
        target_link_libraries(DetouristInstructionConfigTests PRIVATE detourist_common)
        target_include_directories(DetouristInstructionConfigTests SYSTEM PRIVATE "${detourist_dr_root}/include")
        target_compile_definitions(DetouristInstructionConfigTests PRIVATE WINDOWS ${detourist_dr_architecture})
        target_compile_options(DetouristInstructionConfigTests PRIVATE ${detourist_cxx_options})
        add_dependencies(DetouristInstructionConfigTests DetouristInstructions)
        add_test(NAME instruction_configuration COMMAND DetouristInstructionConfigTests)
        set_tests_properties(instruction_configuration PROPERTIES TIMEOUT 15 RUN_SERIAL TRUE LABELS "instructions")
    endif()
    install(TARGETS DetouristInstructions RUNTIME DESTINATION .)
    install(DIRECTORY "${detourist_dr_output}/instruction/" DESTINATION instruction)
    install(FILES "${detourist_dr_root}/License.txt" DESTINATION licenses RENAME DynamoRIO.txt)
endif()
