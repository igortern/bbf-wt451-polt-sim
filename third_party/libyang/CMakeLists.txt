# libyang - YANG support library
#
include(third_party)

set(LIBYANG_PACKAGE_VERSION "1.0.130")

bcm_3rdparty_module_name(libyang "v${LIBYANG_PACKAGE_VERSION}")

if(NETCONF_TOOLS_FROM_DEVEL)
    set(LIBYANG_VERSION devel)
    bcm_3rdparty_download_wget("https://github.com/CESNET/libyang/archive" "devel.zip" "libyang-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/CESNET/libyang/archive" "${LIBYANG_VERSION}.tar.gz" libyang-${LIBYANG_PACKAGE_VERSION})
endif()

bcm_3rdparty_add_dependencies(pcre)

bcm_3rdparty_add_build_options(-DENABLE_BUILD_TESTS=OFF -DENABLE_VALGRIND_TESTS=OFF -DPLUGINS_DIR=lib/libyang)
bcm_3rdparty_add_build_options(-DPLUGINS_DIR:PATH="${CMAKE_BINARY_DIR}/fs/lib/libyang")

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
