# gttlvutil TEST-README

This document describes how to configure and run `gttlvutil` automated test. Also brief overview of the dependencies and files related to the tests is given.

Tests can be run with `gttlvutil` package installed on the machine, or within the project directory. On Unix platform executables are located in `src` directory. If the executables are present in the project directory then the tests are run with the corresponding binaries, otherwise the installed binaries are used.

Unit tests are using default description files. To run tests with description files from `src` directory, configuration option `--with-data-dir=-` must be used. See `./configure -h` for more information.


## DEPENDENCIES

* `shelltestrunner` - mandatory for every test.


## TEST RELATED FILES

All files related to the tests can be found from directory `test` that is located in `gttlvutil` root directory.

```
resource        - directory containing all test resource files
                  (e.g. signatures, server responses);
test_suites     - directory containing all test suites;
test.sh         - use to run tests on Unix platform.
```


## CONFIGURING TESTS

No extra configuration needs to be done prior to execution of test script.


## RUNNING TESTS

Tests must be run from `gttlvutil` root directory, by executing `test.sh` script found in `test` folder to ensure that test environment is configured properly. The exit code is `0` on success and `1` on failure.

To run tests on RHEL/CentOS:

```
test/test.sh
```
