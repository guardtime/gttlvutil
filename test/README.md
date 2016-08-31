# GTTLVUTILs TEST README #

This document describes how to configure and run gttlvutil automated test.
Additionally, the dependences and brief overview of files related to the
tests will be described.

Tests can be run with gttlvutil package installed on the machine.




## DEPENDECES ##

* shelltestrunner - mandatory for every test.




## TEST RELATED FILES ##

All files related to the tests can be found from directory `test` that is
located in gttlvutil root directory.

| File        | Description                           |
| :---        | :---                                  |
| resource    | directory containing all test resource files (e.g. signatures, server responses).|
| test_suites | directory containing all test suites. |
| test.sh     | run tests on unix platform.           |




## CONFIGURING TESTS ##

No extra configuration needs to be done prior to execution of test script.




## RUNNING TESTS ##

Tests must be run from gttlvutil root directory, by executing `test.sh` script
found in `test` folder to ensure that test environment is configured
properly. The exit code is 0 on success and 1 on failure.

To run tests on RHEL/CentOS:
 
```
  test/test.sh
```
 