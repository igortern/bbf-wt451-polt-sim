# Netconf modules
if(NETCONF_SERVER)
    bcm_module_name(netconf_modules)
    bcm_module_dependencies(PUBLIC os dev_log sysrepo libnetconf2 netconf_bbf-xpon)
    if(NOT OPEN_SOURCE)
        bcm_module_dependencies(PUBLIC api)
    endif()
    if(TR451_VOMCI_POLT)
        bcm_module_dependencies(PUBLIC netconf_bbf-polt-vomci)
    endif()
    bcm_module_header_paths(PUBLIC .)
    bcm_module_srcs(
        b64.c
        bcmolt_netconf_module_utils.c
        bcmolt_netconf_module_init.c
        bcmolt_netconf_notifications.c)
    bcm_create_lib_target()

    if (NOT OPEN_SOURCE)
        bcm_add_subdirectory(bbf-xpon)
    else()
        bcm_add_subdirectory(bbf-xpon-dummy)
    endif()
    if(TR451_VOMCI_POLT)
        bcm_add_subdirectory(bbf-vomci)
    endif()
endif()
