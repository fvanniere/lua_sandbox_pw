# Lua Sandbox Extensions for Planet-Work

## Overview

Set of extensions for the Mozilla's [Lua Sandbox] (http://mozilla-services.github.io/lua_sandbox/)

## Installation

### Prerequisites
* luasandbox (1.2+) https://github.com/mozilla-services/lua_sandbox

### CMake Build Instructions

    git clone git@git.pw.fr:pw/lua_sandbox_pw.git
    cd lua_sandbox_pw
    mkdir release
    cd release
    cmake -DCMAKE_BUILD_TYPE=release -DENABLE_ALL_EXT=true -DCPACK_GENERATOR=DEB ..
    make
    ctest
    make packages

