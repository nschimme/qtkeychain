include(ECMAddTests)

if (BUILD_WITH_QT6)
    find_package(Qt6 CONFIG COMPONENTS Core Test REQUIRED)
else()
    find_package(Qt5 CONFIG COMPONENTS Core Test REQUIRED)
endif()

if(NOT EMSCRIPTEN)
    ecm_add_tests(basic.cpp LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
    set_property(TARGET basic PROPERTY AUTOMOC ON)
endif()

if(EMSCRIPTEN)
    add_executable(wasm-test-app wasm-test-app/main.cpp)
    target_link_libraries(wasm-test-app PRIVATE ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Core)
    set_property(TARGET wasm-test-app PROPERTY AUTOMOC ON)

    # Add a custom test that runs the Playwright E2E tests
    find_program(NPM_EXECUTABLE npm)
    if(NPM_EXECUTABLE)
        add_test(
            NAME wasm-e2e-test
            COMMAND ${CMAKE_COMMAND} -E env -- "npm" "install" && "npm" "test"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/e2e
        )
        # The test application must be built before we can run the E2E tests
        add_dependencies(wasm-e2e-test wasm-test-app)
    endif()
endif()
