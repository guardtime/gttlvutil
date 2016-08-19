#!/bin/bash

#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2016] Guardtime, Inc
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

# Remove test temporary directory.  
rm -rf test/tmp 2> /dev/null

# Create test temporary directory.
mkdir -p test/tmp

# If tlv utils are available in project directory then use those, 
# otherwise use the ones installed on the machine.
if [ -f src/gttlvgrep ] && 
   [ -f src/gttlvwrap ] && 
   [ -f src/gttlvdump ] && 
   [ -f src/gttlvundump ]; then
  TLVGREP="src/gttlvgrep"
  TLVWRAP="src/gttlvwrap"
  TLVDUMP="src/gttlvdump"
  TLVUNDUMP="src/gttlvundump"
else
  TLVGREP="gttlvgrep"
  TLVWRAP="gttlvwrap"
  TLVDUMP="gttlvdump"
  TLVUNDUMP="gttlvundump"
fi

# Copy test suites to the tmp folder.
cp -r test/test_suites/ test/tmp/test_suites/

# Replace util names.
sed -i -- "s|GTTLVGREP|$TLVGREP|g" test/tmp/test_suites/*.test
sed -i -- "s|GTTLVWRAP|$TLVWRAP|g" test/tmp/test_suites/*.test
sed -i -- "s|GTTLVDUMP|$TLVDUMP|g" test/tmp/test_suites/*.test
sed -i -- "s|GTTLVUNDUMP|$TLVUNDUMP|g" test/tmp/test_suites/*.test

# Gather all test suites.
for f in test/tmp/test_suites/*.test; do
  TEST_SUITES="$TEST_SUITES $f"
done

# Excecute automated tests.
shelltest -c $TEST_SUITES -- -j1
 
exit_code=$?

# Cleanup.  
rm -rf test/tmp 2> /dev/null

exit $exit_code