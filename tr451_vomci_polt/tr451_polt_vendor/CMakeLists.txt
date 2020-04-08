# TR-451 pOLT vendor interface
if(OPEN_SOURCE)
    bcm_add_subdirectory(sim)
else()
    bcm_add_subdirectory(bcm)
endif()
