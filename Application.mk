APP_OPTIM := debug
NDK_TOOLCHAIN_VERSION := clang
#NDK_TOOLCHAIN_VERSION := 4.8
APP_STL := gnustl_static
#APP_ABI := armeabi-v7a armeabi mips x86
APP_ABI := armeabi-v7a armeabi
#APP_STL                 := stlport_static
APP_USE_CPP0X := true
APP_CPPFLAGS := -frtti -fexceptions -Wno-deprecated-register
APP_PLATFORM := android-10