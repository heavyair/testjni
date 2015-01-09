LOCAL_PATH := $(call my-dir)
MY_LOCAL_PATH := $(LOCAL_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := testPcap

LOCAL_CFLAGS := -Wno-write-strings -fpermissive

LOCAL_SRC_FILES:=\
    CnetCard.cpp  Cpcapclass.cpp  nethelper.cpp  pevents.cpp  sniffitem.cpp  testPcap.cpp  trace.cpp
                   
APP_OPTIM := debug
LOCAL_C_INCLUDES := libpcap libnet/include include
LOCAL_STATIC_LIBRARIES := libpcap libnet
include $(BUILD_EXECUTABLE)
include $(MY_LOCAL_PATH)/libpcap/Android.mk
include $(MY_LOCAL_PATH)/libnet/Android.mk
