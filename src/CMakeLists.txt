find_package( XRootD REQUIRED )

add_library( AuthChangeFsUid SHARED
             AuthChangeFsUid.cc AuthChangeFsUid.hh
)

include_directories( ${XROOTD_INCLUDE_DIR} )

add_definitions( -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 )

target_link_libraries( AuthChangeFsUid )

if( Linux )
  set_target_properties( AuthChangeFsUid PROPERTIES
    VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
    SOVERSION ${VERSION_MAJOR}
    CLEAN_DIRECT_OUTPUT 1
  )
endif( Linux )

install( TARGETS AuthChangeFsUid LIBRARY DESTINATION ${LIB_INSTALL_DIR} )
