@ECHO OFF
GOTO copyrightend

	GUARDTIME CONFIDENTIAL

	Copyright (C) [2016] Guardtime, Inc
	All Rights Reserved

	NOTICE:  All information contained herein is, and remains, the
	property of Guardtime Inc and its suppliers, if any.
	The intellectual and technical concepts contained herein are
	proprietary to Guardtime Inc and its suppliers and may be
	covered by U.S. and Foreign Patents and patents in process,
	and are protected by trade secret or copyright law.
	Dissemination of this information or reproduction of this
	material is strictly forbidden unless prior written permission
	is obtained from Guardtime Inc.
	"Guardtime" and "KSI" are trademarks or registered trademarks of
	Guardtime Inc.

:copyrightend

rem To configure the build environment for 32-bit build setenv with /x86 is
rem called. See WinBuild.txt for more information how to choose the right
rem build environment.

call "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x86

rem To avoid the variables to leak out of the script setlocal is called.
setlocal

rem Installer configuration.

set install_machine=32

rem OpenSSL library configuration.

set lib_type=lib
set openssl_dir=C:\path\to\openssl

rem Specify Run-Time Library.

set rtl=MT

rem Specify cryptography provider.
rem In this example gttlvutils are built with Windows native CryptoAPI. 

set hash_provider=CRYPTOAPI

rem Rebuild the gttlvutils.

nmake clean
nmake /S RTL=%rtl% HASH_PROVIDER=%hash_provider% OPENSSL_DIR=%openssl_dir% LIB_TYPE=%lib_type% INSTALL_MACHINE=%install_machine%

endlocal
pause