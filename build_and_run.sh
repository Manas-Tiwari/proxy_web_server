#!/bin/bash

BUILD_DIR="build"
BIN_DIR="bin"
EXECUTABLE="./bin/server"
SERVER_TARGET_NAME="server"

# Create bin and build folder.
mkdir -p $BIN_DIR
mkdir -p $BUILD_DIR

set -e

cd $BUILD_DIR
cmake -S .. -G Ninja 
ninja $SERVER_TARGET_NAME

cd ..
$EXECUTABLE
