[![ci](https://github.com/Technica-Engineering/MKAdaemon/actions/workflows/unittest.yml/badge.svg)](https://github.com/Technica-Engineering/MKAdaemon/actions/workflows/unittest.yml)
# MACsec Key Agreement (MKA) daemon

## 1. About this project

In this repository you will find the open source code for the MKA daemon implemented by Technica Engineering Gmbh.

Currently this daemon supports running in Linux (tested Ubuntu 20.04 and 22.04), and implements MKA as defined in IEEE802.1X-2020. EAP is not supported yet but PSK is fully supported. All MACsec algorithms are supported: GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128 and GCM-AES-XPN-256 (although XPN is not supported with kernel shipped in Ubuntu 20.04).  

## 2. Licensing

This software is available under two distinct licensing models: open source (GLPv2, see COPYING.txt) and standard commercial licensing.

Please contact macsec@technica-engineering.de with inquiries.

## 3. Compiling this project

### 3.1 Dependencies
You will need the following dependencies to compile this software:

 - Python3 (python2 is also known to work for now)
 - Install the following packages ("apt" packages provided for Ubuntu 22.04):
   - build-essential
   - libglib2.0-dev-bin
   - pkg-config
   - libssl-dev
   - libyaml-dev
   - libbsd-dev
   - libnl-3-dev
   - libnl-genl-3-dev
   - libnl-route-3-dev
   - libglib2.0-dev
   - libxml2-dev
   - wireshark (recommended)

Additionally the following dependencies will be necessary to compile and run unit tests:

   - lcov
   - library rt
   - make and cmake

## 3.2 How to compile
Build command:

>   python waf build

Clean command
>   python waf distclean

There are "make" wrappers for easier integration (Yocto/similar): ./configure, make clean, make all, make test, ...

Once compilation finishes, the resulting MKA daemon binary is: **build/mkad**

A command line interface tool is also compiled, which is able to interact and control the MKA daemon using the DBUS interface: **build/mkad\_cli**

Additionally, an example of a configuration file is provided: mkad.conf.example

## 3.3 Unit Testing
Tests are located under folder tests/. Google Test (and Google Mock) are used as framework, GNU GCOV for coverage, LCOV for merging coverage reports and a custom python waf module for orchestrating execution of everything.

Each test folder contains a file wscript with test compilations. Each has a name (that can be referenced via --targets=XXX), and defines how to compile that particular test, defining test code, mocks and unit under test. Only UUT is analysed with code coverage.

In the different modules, (especially for the "core" part src/pae) we try to aim for a code coverage metric of at least 90%.

Since this project references a specific tag of the official GoogleTest repository, please make sure to download git submodules prior to compiling unit tests.

### 3.3.1 How to compile and run Unit Tests

Compile and run all tests:
>   python waf test

Individual tests (useful when implementing a new feature or modifying an existing one):

 - Make sure the root folder is configured
>   python waf configure

 - One option is select the test from the root folder:
>   python waf test --targets=kay

 - Specific tests or test suites can also be selected from the root:
>   python waf test --targets=kay --gtest\_filter=TxWhenClient.*

 - Otherwise, you can also go to the folder of the test (e.g. src/pae/test), then run:
>   python waf test

 - Alternatively, to compile + run a single test (e.g. kay) in that folder, run:
>   python waf test --targets=kay

 - To run a single test case, option gtest\_filter is forwarded to Google Test:
>   python waf test --targets=kay --gtest\_filter=TxWhenClient.InstallSak


### 3.3.1 KAY unit tests 

KAY UT's generate PCAP files with the tested protocol exchange. You can find them in the folder build/pcap after tests execution.

### 3.3.2 Coverage report

You can find a report with the code covered/not covered opening file build/global\_coverage\_report/index.html after tests execution.

### 3.3.3 Other

JUnit-compatible XML files of unit test execution are available for CI automated parsing under folder build.

## 4 The Dbus interface
- In order to use the Dbus interface in a system with policies enabled, you have to add policies to allow it
> cp dbus-policies/de.technica_engineering.mkad.conf /usr/share/dbus-1/system.d/de.technica_engineering.mkad.conf
- Then restart your computer

## 5 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
