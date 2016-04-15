LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=\
pcap-linux.c\
pcap.c\
inet.c\
gencode.c\
optimize.c\
nametoaddr.c\
etherent.c\
savefile.c\
sf-pcap.c\
sf-pcap-ng.c\
pcap-common.c\
bpf_image.c\
bpf_dump.c\
scanner.c\
grammar.c\
bpf_filter.c\
version.c



LOCAL_CFLAGS:=-O2 -g
LOCAL_CFLAGS+=-DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -Dlinux -D__GLIBC__ -D_GNU_SOURCE -Wno-pointer-sign -Wno-format-extra-args

LOCAL_MODULE:= libpcap

include $(BUILD_STATIC_LIBRARY)
