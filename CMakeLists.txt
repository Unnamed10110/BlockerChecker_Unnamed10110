cmake_minimum_required(VERSION 3.10)
project(BlockerChecker)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Main application
add_executable(BlockerChecker main.cpp resource.rc)

# Set output directory
set_target_properties(BlockerChecker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Set Windows-specific properties
if(WIN32)
    set_target_properties(BlockerChecker PROPERTIES
        WIN32_EXECUTABLE TRUE
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
    )
endif()

# Link required libraries
target_link_libraries(BlockerChecker 
    shell32
    advapi32
    comctl32
) 