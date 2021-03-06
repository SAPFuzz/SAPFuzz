# Cable: CMake Bootstrap Library.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_FLAGS_INIT "-fPIC" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_INIT "-fPIC" CACHE STRING "" FORCE)
