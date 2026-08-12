#!/bin/bash
# 一键编译 SSLBypass.dylib
# 在 Mac 上执行：chmod +x build.sh && ./build.sh

set -e

echo "==> 检查 Xcode SDK..."
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
if [ -z "$SDK_PATH" ]; then
    echo "错误：未找到 iPhoneOS SDK，请先安装 Xcode"
    echo "执行：xcode-select --install"
    exit 1
fi
echo "SDK 路径: $SDK_PATH"

echo "==> 编译 arm64 dylib..."
clang -arch arm64 -dynamiclib -o SSLBypass.dylib SSLBypass_standalone.m \
  -framework Foundation -framework Security -framework CoreFoundation \
  -miphoneos-version-min=14.0 \
  -isysroot "$SDK_PATH"

echo "==> 编译完成！"
ls -lh SSLBypass.dylib
echo ""
echo "下一步：把 SSLBypass.dylib 传到手机，用 TrollFools 注入今日头条"
