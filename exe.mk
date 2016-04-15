LOCAL_PATH := $(call my-dir)
MY_LOCAL_PATH := $(LOCAL_PATH)
MY_PCAP_PATH := $(LOCAL_PATH)
include $(CLEAR_VARS)

LOCAL_CFLAGS :=  -Wall -c  -DCOMMONFILE=\"nbtscan_common.h\" -fmessage-length=0  -Wno-write-strings -fpermissive -Wno-narrowing -Wno-format-extra-args -ffunction-sections -fdata-sections -fvisibility=hidden 

#LOCAL_CPPFLAGS := -D__cplusplus=201103L -std=gnu++11 -pthread -frtti -fexceptions
LOCAL_CPPFLAGS := -DCPUFEATURE=1 -pthread -frtti -fexceptions  -Wall -c -DCOMMONFILE=\"nbtscan_common.h\" -fmessage-length=0  -Wno-write-strings -fpermissive -std=gnu++11 -Wno-narrowing -Wno-format-extra-args -ffunction-sections -fdata-sections -fvisibility=hidden 

LOCAL_CPP_EXTENSION := .cpp

LOCAL_CFLAGS    += -DHAVE_STDINT_H=1 
LOCAL_CFLAGS    += -g
LOCAL_CFLAGS    += -ggdb
LOCAL_CFLAGS    += -O0

LOCAL_CPPFLAGS += -DHAVE_STDINT_H=1
LOCAL_CPPFLAGS += -g
LOCAL_CPPFLAGS += -ggdb
LOCAL_CPPFLAGS += -O0

FILE_LIST := $(wildcard $(LOCAL_PATH)/tins/*.cpp $(LOCAL_PATH)/md5/*.cpp $(LOCAL_PATH)/libnfnetlink/src/*.c $(LOCAL_PATH)/libnetfilter_queue/src/*.c $(LOCAL_PATH)/libmnl/src/*.c)

LOCAL_SRC_FILES := $(FILE_LIST:$(LOCAL_PATH)/%=%)


LOCAL_SRC_FILES +=\
nbt/all_digitsA.c\
nbt/byteswap_nodestats.c\
nbt/die.c\
nbt/display_nbtstat.c\
nbt/dump_packet.c\
nbt/errors.c\
nbt/gen_perl.c\
nbt/hostname.c\
nbt/lookup_hostname.c\
nbt/netbios_fixname.c\
nbt/netbios_name.c\
nbt/netbios_pack.c\
nbt/netbios_unpack.c\
nbt/netmasks.c\
nbt/nstrcpyA.c\
nbt/packetio.c\
nbt/parse_inaddr.c\
nbt/parse_nbtstat.c\
nbt/parse_target.c\
nbt/parse_target_cb.c\
nbt/printable_NETBIOS_question_class.c\
nbt/printable_NETBIOS_question_type.c\
nbt/process_response.c\
nbt/sleep_msecs.c\
nbt/stripA.c\
nbt/targets.c\
nbt/timeval_set_secs.c\
nbt/version.c\
nbt/winsock.c\
libpcap/ifaddrs.c
#FILE_LIST := $(wildcard $(LOCAL_PATH)/extensions/*.c)

LOCAL_SRC_FILES+=$(wildcard $(MY_PCAP_PATH)/*.cpp  $(MY_PCAP_PATH)/os/*.cpp $(MY_PCAP_PATH)/zlib/*.c $(MY_PCAP_PATH)/os/linux/*.cpp)



                   
APP_OPTIM := debug
LOCAL_C_INCLUDES := $(MY_PCAP_PATH)/zlib $(MY_PCAP_PATH)/os $(MY_PCAP_PATH)/os/linux $(MY_PCAP_PATH)/ libpcap libnet/include tins tins/tins nbt md5 libnetfilter_queue libnetfilter_queue/libnetfilterqueue_include libnfnetlink/libnfnetlink_include libmnl libmnl/libmnl_include

LOCAL_STATIC_LIBRARIES := libpcap libnet cpufeatures
include $(BUILD_EXECUTABLE)
include $(MY_LOCAL_PATH)/libpcap/Android.mk
include $(MY_LOCAL_PATH)/libnet/Android.mk

$(call import-module,android/cpufeatures)