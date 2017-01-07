
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH),arm)
LOCAL_CFLAGS	+= -D__ARM__=1 -D__arm__=1 
endif

ifeq ($(TARGET_ARCH),x86)
LOCAL_CFLAGS	+= -D__X86__=1 -D__PC__=1
endif

LOCAL_SRC_FILES := arm_debmod.cpp debmod.cpp fpro.cpp kernwin.cpp linuxbase_debmod.cpp linux_debmod.cpp linux_threads.cpp\
 	linux_wait.cpp pro.cpp rpc_engine.cpp rpc_hlp.cpp rpc_server.cpp server.cpp symelf.cpp tcpip.cpp util.cpp \
 	err.cpp diskio.cpp pc_debmod.cpp prodir.cpp 
LOCAL_MODULE    := android_server
LOCAL_CFLAGS	+= -D__LINUX__=1 -DUSE_STANDARD_FILE_FUNCTIONS=1 -DRPC_CLIENT=1 -D__ANDROID__=1
LOCAL_CPPFLAGS	+= -fexceptions
LOCAL_LDLIBS	:= -llog
include $(BUILD_EXECUTABLE)


