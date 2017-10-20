#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2015] Guardtime, Inc
# All Rights Reserved
#
# NOTICE:  All information contained herein is, and remains, the
# property of Guardtime Inc and its suppliers, if any.
# The intellectual and technical concepts contained herein are
# proprietary to Guardtime Inc and its suppliers and may be
# covered by U.S. and Foreign Patents and patents in process,
# and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this
# material is strictly forbidden unless prior written permission
# is obtained from Guardtime Inc.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime Inc.
#

!IF "$(LIB_TYPE)" != "lib" && "$(LIB_TYPE)" != "dll"
LIB_TYPE = lib
!ENDIF

!IFNDEF RTL
RTL = MT
!MESSAGE Setting C Runtime Lib to MT
!ELSE IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
!ERROR RTL can only have one of the following values "MT", "MTd", "MD" or "MDd", but it is "$(RTL)". Default value is "MT".
!ENDIF

!IFNDEF INSTALL_MACHINE
!MESSAGE Setting INSTALL_MACHINE to default
INSTALL_MACHINE=64
!ELSE IF "$(INSTALL_MACHINE)" != "32" && "$(INSTALL_MACHINE)" != "64"
!ERROR set INSTALL_MACHINE=32 or INSTALL_MACHINE=64
!ENDIF

#Compiler and linker configuration
CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) /DDATA_DIR="\"\""
LDFLAGS = /NOLOGO

#external libraries used for linking.
EXT_LIB = user32.lib gdi32.lib advapi32.lib

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TOOL_NAME = gttlvutil
DUMP_NAME = gttlvdump
WRAP_NAME = gttlvwrap
GREP_NAME = gttlvgrep
UNDUMP_NAME = gttlvundump

VERSION_FILE = VERSION

DUMP_OBJ = \
	$(OBJ_DIR)\tlvdump.obj \
	$(OBJ_DIR)\getopt.obj \
	$(OBJ_DIR)\fast_tlv.obj \
	$(OBJ_DIR)\desc.obj \
	$(OBJ_DIR)\dir.obj \
	$(OBJ_DIR)\encoding.obj \
	$(OBJ_DIR)\compatibility.obj \
	$(OBJ_DIR)\file_io.obj \
	$(OBJ_DIR)\common.obj

WRAP_OBJ = \
	$(OBJ_DIR)\tlvwrap.obj \
	$(OBJ_DIR)\getopt.obj \
	$(OBJ_DIR)\encoding.obj \
	$(OBJ_DIR)\file_io.obj \
	$(OBJ_DIR)\common.obj

GREP_OBJ = \
	$(OBJ_DIR)\tlvgrep.obj \
	$(OBJ_DIR)\grep_tlv.obj \
	$(OBJ_DIR)\fast_tlv.obj \
	$(OBJ_DIR)\getopt.obj \
	$(OBJ_DIR)\encoding.obj \
	$(OBJ_DIR)\compatibility.obj \
	$(OBJ_DIR)\file_io.obj \
	$(OBJ_DIR)\common.obj

UNDUMP_OBJ = \
	$(OBJ_DIR)\tlvundump.obj \
	$(OBJ_DIR)\getopt.obj \
	$(OBJ_DIR)\fast_tlv.obj \
	$(OBJ_DIR)\hash.obj \
	$(OBJ_DIR)\compatibility.obj \
	$(OBJ_DIR)\grep_tlv.obj \
	$(OBJ_DIR)\common.obj

#Selecting hash provider
!IF "$(HASH_PROVIDER)" == "OPENSSL"
CCFLAGS = $(CCFLAGS) /DCRYPTO_IMPL=HASH_OPENSSL
UNDUMP_OBJ = $(UNDUMP_OBJ) $(OBJ_DIR)\hmac_openssl.obj
!ELSE IF "$(HASH_PROVIDER)" == "CRYPTOAPI"
CCFLAGS = $(CCFLAGS) /DCRYPTO_IMPL=HASH_CRYPTOAPI
UNDUMP_OBJ = $(UNDUMP_OBJ) $(OBJ_DIR)\hmac_cryptoapi.obj
!ENDIF

DESC_FILES = \
	$(SRC_DIR)\ksi.desc \
	$(SRC_DIR)\ksie.desc \
	$(SRC_DIR)\logsig.desc


!IF "$(HASH_PROVIDER)" == "OPENSSL"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\$(LIB_TYPE)"
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).lib
!ENDIF

!IF "$(HASH_PROVIDER)" == "CRYPTOAPI"
EXT_LIB = $(EXT_LIB) Crypt32.lib
!ENDIF


!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF

!IFDEF DESC_DIR
CCFLAGS = $(CCFLAGS) /DDATA_DIR=\"$(DESC_DIR)\"
!ENDIF

VER = \
!INCLUDE <$(VERSION_FILE)>

!IF "$(VER)" != ""
CCFLAGS = $(CCFLAGS) /DVERSION=\"$(VER)\" /DPACKAGE_NAME=\"$(TOOL_NAME)\"
!ENDIF


#Making


default: $(BIN_DIR)\$(DUMP_NAME).exe $(BIN_DIR)\$(WRAP_NAME).exe $(BIN_DIR)\$(GREP_NAME).exe $(BIN_DIR)\$(UNDUMP_NAME).exe



$(BIN_DIR)\$(DUMP_NAME).exe: $(BIN_DIR) $(OBJ_DIR) $(DUMP_OBJ)
	link $(LDFLAGS) /OUT:$@ $(DUMP_OBJ) $(EXT_LIB)
	for %I in ($(DESC_FILES)) do copy %I $(BIN_DIR)\ /Y

$(BIN_DIR)\$(WRAP_NAME).exe: $(BIN_DIR) $(OBJ_DIR) $(WRAP_OBJ)
	link $(LDFLAGS) /OUT:$@ $(WRAP_OBJ) $(EXT_LIB)

$(BIN_DIR)\$(GREP_NAME).exe: $(BIN_DIR) $(OBJ_DIR) $(GREP_OBJ)
	link $(LDFLAGS) /OUT:$@ $(GREP_OBJ) $(EXT_LIB)

$(BIN_DIR)\$(UNDUMP_NAME).exe: $(BIN_DIR) $(OBJ_DIR) $(UNDUMP_OBJ)
	link $(LDFLAGS) /OUT:$@ $(UNDUMP_OBJ) $(EXT_LIB)

{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<




#Folder factory

$(OBJ_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@


installer:$(BIN_DIR) $(OBJ_DIR) $(BIN_DIR)\$(DUMP_NAME).exe $(BIN_DIR)\$(WRAP_NAME).exe $(BIN_DIR)\$(GREP_NAME).exe $(BIN_DIR)\$(UNDUMP_NAME).exe
!IF [candle.exe > nul] != 0
!MESSAGE Please install WiX to build installer.
!ELSE
	cd windows
	candle.exe $(TOOL_NAME).wxs -o ..\$(OBJ_DIR)\$(TOOL_NAME).wixobj \
	-dVersion="1.0.0" \
	-dName=$(TOOL_NAME) \
	-ddumpName=$(BIN_DIR)\$(DUMP_NAME).exe \
	-dwrapName=$(BIN_DIR)\$(WRAP_NAME).exe \
	-dgrepName=$(BIN_DIR)\$(GREP_NAME).exe \
	-dundumpName=$(BIN_DIR)\$(UNDUMP_NAME).exe \
	-darch=$(INSTALL_MACHINE)
	light.exe ..\$(OBJ_DIR)\$(TOOL_NAME).wixobj -o ..\$(BIN_DIR)\$(TOOL_NAME) -pdbout ..\$(BIN_DIR)\$(TOOL_NAME).wixpdb -cultures:en-us -ext WixUIExtension
	cd ..
!ENDIF

clean:
	@for %i in ($(OBJ_DIR) $(BIN_DIR)) do @if exist .\%i rmdir /s /q .\%i

