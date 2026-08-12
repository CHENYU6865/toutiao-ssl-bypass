# SSL Pinning Bypass dylib（TrollFools 注入专用）

## 文件说明
| 文件 | 用途 |
|------|------|
| `SSLBypass_standalone.m` | **推荐**，独立版，内嵌 fishhook，无外部依赖，clang 直接编译 |
| `SSLBypass.m` | Theos 版，需要 fishhook 库 |
| `Makefile` + `control` | Theos 工程文件 |

---

## 一、编译（必须在 Mac 上操作）

### 方式 A：clang 直接编译（最简单，推荐）

打开终端，进入本目录，执行：

```bash
clang -arch arm64 -dynamiclib -o SSLBypass.dylib SSLBypass_standalone.m \
  -framework Foundation -framework Security -framework CoreFoundation \
  -miphoneos-version-min=14.0 \
  -isysroot $(xcrun --sdk iphoneos --show-sdk-path)
```

编译成功后当前目录会生成 `SSLBypass.dylib`。

> 如果报 `xcrun: error`，说明没装 Xcode Command Line Tools，先执行：
> `xcode-select --install`

### 方式 B：Theos 编译

```bash
# 把 SSLBypass_standalone.m 改名为 Tweak.xm（或在 Makefile 里指定 FILES）
make clean && make package
# 产物在 packages/ 目录下，解压 deb 取出 Library/MobileSubstrate/DynamicLibraries/SSLBypass.dylib
```

---

## 二、TrollFools 注入步骤

### 前置条件
- 设备已安装 TrollStore（巨魔）
- 已安装 TrollFools（从巨魔商店安装）
- 今日头条已安装（从 App Store 安装即可，**不需要砸壳**）

### 注入操作
1. 把编译好的 `SSLBypass.dylib` 传到手机（AirDrop / 文件 App / 任意方式）
2. 打开 **TrollFools**
3. 选择「今日头条」（App 列表里点进去）
4. 点击「Inject dylib」或「添加 dylib」
5. 选择你传入的 `SSLBypass.dylib`
6. 等待注入完成，TrollFools 会自动重新注册 App
7. 回到桌面，**重新打开今日头条**

> 注入后 App 图标可能会变，属于正常现象。
> 如果闪退，卸载头条重装后重新注入。

---

## 三、抓包配置

### 1. 安装 CA 证书
- 电脑端打开 Charles / mitmproxy / Burp Suite
- 手机 WiFi 设置代理为电脑 IP + 端口
- 手机 Safari 访问 `chls.pro/ssl`（Charles）或 `mitm.it`（mitmproxy）下载证书
- 设置 → 通用 → VPN与设备管理 → 安装证书
- **关键**：设置 → 通用 → 关于本机 → 证书信任设置 → 打开对应证书的完全信任

### 2. 开始抓包
- 确保手机和电脑同一局域网
- 打开今日头条，操作 App
- 电脑端抓包工具即可看到解密后的 HTTPS 请求

---

## 四、已知限制与排错

### 能抓到的流量
- 所有走系统 `NSURLSession` / `CFNetwork` 的请求（大部分 UI 接口、评论、搜索等）

### 可能抓不到的流量
- 字节跳动自研 native 网络库（TTNet / Cronet 等）的请求
- 视频流媒体流量
- 这部分需要额外逆向 hook native 层 TLS 函数，本 dylib 不覆盖

### 常见问题
| 现象 | 原因 | 解决 |
|------|------|------|
| 注入后 App 闪退 | 头条检测到注入 / 架构不对 | 确认编译了 arm64，用小号测试 |
| 还是抓不到包 | 证书没开完全信任 / 代理没设对 | 检查证书信任设置，用 Safari 开任意 https 网站验证 |
| 部分接口抓不到 | native 网络库 | 需要定制 hook，超出本 dylib 范围 |
| TrollFools 注入失败 | 版本不兼容 | 更新 TrollStore 和 TrollFools 到最新版 |

### 账号风险提示
- 注入修改后的 App 登录正式账号**有风控封号风险**
- 务必用小号测试
- 不要长时间高频请求

---

## 五、卸载 / 恢复
- TrollFools 里选择头条 → 移除注入的 dylib
- 或直接卸载头条重装
