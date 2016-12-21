project (myadb)
ADD_DEFINITIONS(-DUNICODE -D_UNICODE -DHAVE_WINSOCK -DADB_HOST -DHAVE_WIN32_PROC -D_WINSOCKAPI_ -DHAVE_WIN32_IPC -D_XOPEN_SOURCE -DADBWIN_EXPORTS)
INCLUDE_DIRECTORIES (${COMMON_INCLUDE} . .. ${EXT_DIR}/openssl ${EXT_DIR}/adbdevdetect ${COMMON_INCLUDE}/../src/Common ${COMMON_INCLUDE}/../ext/winusb)
FILE (GLOB header_files *.h)
FILE (GLOB source_files *.c *.cpp)
SET(SRC_LIST1 ./sysdeps/win32/stat.cpp)

LINK_DIRECTORIES(${COMMON_LIB})

ADD_EXECUTABLE (myadb ${header_files} ${source_files} ${SRC_LIST1})

IF(WIN32)

TARGET_LINK_LIBRARIES (myadb ws2_32 Setupapi winusb psapi libeay32 ssleay32 adbdevdetect getopt)

ELSE()

TARGET_LINK_LIBRARIES (myadb)

ENDIF(WIN32)
