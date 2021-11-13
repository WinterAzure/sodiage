#!/bin/bash

CC=clang-12
CXX=clang++-12
EXECABLE_NAME=sodiage
EXTRA_LINK='-lssl -lcrypto'

if [ -z $1 ]; then
    echo 'Usage:[debug|derun|clean|release]'
    exit
fi

if [ $1 = vscode ];then
    SOURCES=$(ls ../src/*.c ../src/third_part/*.c)
    $CC -g $SOURCES -o ../build/$EXECABLE_NAME $(pkg-config --libs libsodium) $EXTRA_LINK
    exit
else
    SOURCES=$(ls ./src/*.c ./src/third_part/*.c)
fi

if [ $1 = debug ]; then
    echo 'Debug release compile.'
    $CC -g $SOURCES -o ./build/$EXECABLE_NAME $(pkg-config --libs libsodium) $EXTRA_LINK
    if [ $? -ne 0 ]; then
        echo 'Compile Failed!'
    else
        echo 'Compile Succeed!'
    fi
fi

if [ $1 = derun ]; then
    echo 'Run debug release.'
    $CC -g $SOURCES -o ./build/$EXECABLE_NAME $(pkg-config --libs libsodium) $EXTRA_LINK
    if [ $? -ne 0 ]; then
        echo 'Compile Failed!'
    else
        echo 'Compile Succeed!'
        ./build/$EXECABLE_NAME
    fi
fi

if [ $1 = clean ]; then
    echo 'Clean files.'
    rm -rf ./build/*
fi

if [ $1 = release ]; then
    echo 'Release release compile.'
    $CC -Ofast $SOURCES -o $EXECABLE_NAME $(pkg-config --libs libsodium) $EXTRA_LINK
    if [ $? -ne 0 ]; then
        echo 'Compile Failed!'
    else
        echo 'Compile Succeed!'
    fi
fi
