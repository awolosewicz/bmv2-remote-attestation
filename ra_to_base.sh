#!/bin/bash

#Compile your chosen version of BMv2 (tested on commit e9fa7dc687f334e5cf327e0c993fc1a351d224c0)
#Then install it, find where it installed the given files below, and set the variables accordingly
#Then compile this repo and run this script with sudo

#In-repo paths
SSWITCH_LIB=targets/simple_switch/.libs
THRIFT_LIB=thrift_src/.libs
THRIFT_CPP=thrift_src/gen-cpp/bm
THRIFT_PY=thrift_src/gen-py/bm_runtime/
SRC_LIB=src/.libs
#Machine paths
BIN=/usr/local/bin
LIB=/usr/local/lib
INCLUDE=/usr/local/include
PYTHON=/usr/local/lib/python3.8/site-packages

cp $SSWITCH_LIB/simple_switch $BIN/simple_switch
cp $THRIFT_LIB/libruntimestubs.so.0.0.0 $LIB/libruntimestubs.so.0.0.0
cp $THRIFT_LIB/libruntimestubs.a $LIB/libruntimestubs.a
cp tools/runtime_CLI.py $PYTHON/runtime_CLI.py
cp -r $THRIFT_PY $PYTHON/
cp $THRIFT_CPP/Standard.h $INCLUDE/bm/Standard.h
cp $SRC_LIB/libbmall.so.0.0.0 $LIB/libbmall.so.0.0.0
cp $SRC_LIB/libbmall.a $LIB/libbmall.a
