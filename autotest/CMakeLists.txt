include(ECMAddTests)

if (BUILD_WITH_QT6)
    find_package(Qt6 CONFIG COMPONENTS Test REQUIRED)
else()
    find_package(Qt5 CONFIG COMPONENTS Test REQUIRED)
endif()

if(NOT EMSCRIPTEN)
    ecm_add_tests(basic.cpp LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
    set_property(TARGET basic PROPERTY AUTOMOC ON)
endif()

if(EMSCRIPTEN)
    ecm_add_tests(wasm/tst_wasm.cpp
        LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
    set_property(TARGET tst_wasm PROPERTY AUTOMOC ON)
endif()
