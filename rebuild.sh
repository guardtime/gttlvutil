#!/bin/sh

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

PRF=gttlvutil-$(tr -d [:space:] < VERSION)

if [ $# -eq 0 ]; then
  conf_args="--with-data-dir=-"
else
  conf_args=$* 
fi

rm -f ${PRF}*.tar.gz && \
mkdir -p config m4 && \
echo Running autoreconf... && \
autoreconf -if && \
echo Running configure script... && \
./configure $conf_args && \
echo Running make... && \
make clean && \
make \
