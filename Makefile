DEBUG=0
FINALPACKGE=1

ARCHS = arm64
GO_EASY_ON_ME=1

TARGET := iphone:clang:latest:7.0
INSTALL_TARGET_PROCESSES = trolldecryptor

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = trolldecryptor

trolldecryptor_FILES = SSZipArchive/minizip/unzip.c SSZipArchive/minizip/crypt.c SSZipArchive/minizip/ioapi_buf.c SSZipArchive/minizip/ioapi_mem.c SSZipArchive/minizip/ioapi.c SSZipArchive/minizip/minishared.c SSZipArchive/minizip/zip.c SSZipArchive/minizip/aes/aes_ni.c SSZipArchive/minizip/aes/aescrypt.c SSZipArchive/minizip/aes/aeskey.c SSZipArchive/minizip/aes/aestab.c SSZipArchive/minizip/aes/fileenc.c SSZipArchive/minizip/aes/hmac.c SSZipArchive/minizip/aes/prng.c SSZipArchive/minizip/aes/pwd2key.c SSZipArchive/minizip/aes/sha1.c SSZipArchive/SSZipArchive.m
trolldecryptor_FILES += DumpDecrypted.m main.m AppDelegate.m RootViewController.m
trolldecryptor_FRAMEWORKS = UIKit CoreGraphics
trolldecryptor_CFLAGS = -fno-objc-arc

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	rm -rf Payload
	mkdir -p $(THEOS_STAGING_DIR)/Payload
	ldid -Sent.plist $(THEOS_STAGING_DIR)/Applications/trolldecryptor.app/trolldecryptor
	cp -a $(THEOS_STAGING_DIR)/Applications/* $(THEOS_STAGING_DIR)/Payload
	mv $(THEOS_STAGING_DIR)/Payload .
	zip -q -r TrollDecryptor.ipa Payload
