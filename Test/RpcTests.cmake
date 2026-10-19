find_program(detourist_midl midl.exe PATHS
    "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64" REQUIRED)
set(detourist_rpc_directory "${CMAKE_BINARY_DIR}/generated/rpc")
file(MAKE_DIRECTORY "${detourist_rpc_directory}")
set(detourist_rpc_sources)
set(detourist_rpc_variants 32)
set(detourist_rpc_environment win32)
set(detourist_rpc_object_protocol dce)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND detourist_rpc_variants 64)
    set(detourist_rpc_environment x64)
    set(detourist_rpc_object_protocol all)
endif()
foreach(variant IN LISTS detourist_rpc_variants)
    set(DETOURIST_RPC_NAME "DetouristRpc${variant}")
    if(variant EQUAL 32)
        set(DETOURIST_RPC_UUID "968ed5a4-c8c2-46d3-9263-55de59782f78")
        set(detourist_rpc_protocol dce)
    else()
        set(DETOURIST_RPC_UUID "77849780-a726-48b4-aba9-94c6e33deff7")
        set(detourist_rpc_protocol ndr64)
    endif()
    set(rpc "${detourist_rpc_directory}/${DETOURIST_RPC_NAME}")
    configure_file(Test/RpcFixture.idl.in "${rpc}.idl" @ONLY NEWLINE_STYLE CRLF)
    configure_file(Test/RpcFixture.acf.in "${rpc}.acf" @ONLY NEWLINE_STYLE CRLF)
    add_custom_command(OUTPUT "${rpc}.h" "${rpc}_c.c" "${rpc}_s.c"
        COMMAND "${detourist_midl}" /nologo /no_cpp /env ${detourist_rpc_environment}
            /target NT100 /Oicf /robust /protocol ${detourist_rpc_protocol}
            /prefix client Client_ /prefix server Server_ /out "${detourist_rpc_directory}"
            /acf "${rpc}.acf" "${rpc}.idl"
        DEPENDS "${rpc}.idl" "${rpc}.acf" VERBATIM)
    list(APPEND detourist_rpc_sources "${rpc}_c.c" "${rpc}_s.c" "${rpc}.h")
endforeach()
set(rpc_object "${detourist_rpc_directory}/RpcObjectFixture")
add_custom_command(OUTPUT "${rpc_object}.h" "${rpc_object}_p.c" "${rpc_object}_i.c"
        "${rpc_object}_dlldata.c"
    COMMAND "${detourist_midl}" /nologo /env ${detourist_rpc_environment}
        /Oicf /robust /protocol ${detourist_rpc_object_protocol}
        /cpp_cmd cl.exe /I "${detourist_sdk_include}/shared"
        /I "${detourist_sdk_include}/um" /I "${detourist_msvc_include}"
        /out "${detourist_rpc_directory}" /dlldata "${rpc_object}_dlldata.c"
        "${CMAKE_SOURCE_DIR}/Test/RpcObjectFixture.idl"
    DEPENDS Test/RpcObjectFixture.idl WORKING_DIRECTORY "${detourist_compiler_directory}" VERBATIM)
add_library(detourist_rpc_object OBJECT "${rpc_object}_p.c" "${rpc_object}_i.c" "${rpc_object}_dlldata.c")
target_link_libraries(detourist_rpc_object PRIVATE detourist_common)
add_executable(DetouristRpcTests Test/RpcTests.cpp Test/RpcObjectMetadata.c ${detourist_rpc_sources})
target_include_directories(DetouristRpcTests PRIVATE "${detourist_rpc_directory}")
target_link_libraries(DetouristRpcTests PRIVATE detourist_test_support detourist_common detourist_rpc_object rpcrt4)
target_compile_options(DetouristRpcTests PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:${detourist_cxx_options}>")
add_dependencies(DetouristRpcTests DetouristCollector)
add_test(NAME rpc_ndr COMMAND DetouristRpcTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(rpc_ndr PROPERTIES TIMEOUT 240 LABELS "coverage;rpc")
add_test(NAME rpc_marshal_lifecycle COMMAND DetouristRpcTests $<TARGET_FILE:DetouristCollector> --lifecycle)
set_tests_properties(rpc_marshal_lifecycle PROPERTIES TIMEOUT 180 LABELS "coverage;rpc;lifecycle")

add_executable(DetouristRpcDcomTests Test/RpcDcomTests.cpp)
target_include_directories(DetouristRpcDcomTests PRIVATE "${detourist_rpc_directory}")
target_link_libraries(DetouristRpcDcomTests PRIVATE detourist_test_support detourist_common detourist_rpc_object rpcrt4)
target_compile_options(DetouristRpcDcomTests PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:${detourist_cxx_options}>")
add_dependencies(DetouristRpcDcomTests DetouristCollector)
add_test(NAME rpc_dcom COMMAND DetouristRpcDcomTests $<TARGET_FILE:DetouristCollector>)
set_tests_properties(rpc_dcom PROPERTIES TIMEOUT 240 LABELS "coverage;rpc")
