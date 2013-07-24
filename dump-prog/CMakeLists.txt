include_directories(${pe-parse_SOURCE_DIR}/parser-library)

add_executable( dump-prog 
                dump.cpp )

target_link_libraries(  dump-prog 
                        parser-library )
