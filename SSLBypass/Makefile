ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = 今日头条

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SSLBypass

SSLBypass_FILES = SSLBypass.m
SSLBypass_CFLAGS = -fobjc-arc
SSLBypass_FRAMEWORKS = Foundation Security CoreFoundation

include $(THEOS_MAKE_PATH)/tweak.mk
