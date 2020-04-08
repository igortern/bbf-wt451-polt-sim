# TR-451 pOLT vendor interface
if(OPEN_SOURCE)
    add_subdirectory(sim)
else()
    add_subdirectory(bcm)
endif()
