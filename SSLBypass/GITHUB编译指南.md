# 无 Mac 编译方案：GitHub Actions 在线编译

## 操作步骤（5分钟搞定）

### 1. 注册/登录 GitHub
https://github.com

### 2. 新建仓库
- 点右上角 `+` → `New repository`
- 仓库名随便填，比如 `SSLBypass`
- 选 **Public**（公开仓库免费额度够用）
- 勾选 `Add a README file`
- 点 `Create repository`

### 3. 上传文件
在仓库页面：
- 点 `Add file` → `Upload files`
- 把整个 SSLBypass 文件夹里的**所有文件和文件夹**拖进去（包括 `.github` 文件夹）
  - `SSLBypass_standalone.m`
  - `SSLBypass.m`
  - `Makefile`
  - `control`
  - `build.sh`
  - `README.md`
  - `.github/workflows/build.yml` ← 这个最重要
- 底部点 `Commit changes`

### 4. 等待自动编译
- 点仓库顶部的 **Actions** 标签
- 能看到一个正在运行的 workflow（黄色转圈）
- 等 2-3 分钟，变成绿色对勾 ✓

### 5. 下载 dylib
- 点进那个绿色的 workflow run
- 页面最底部 **Artifacts** 区域
- 点 `SSLBypass.dylib` 下载
- 解压得到 `SSLBypass.dylib`

### 6. 注入手机
- 把 `SSLBypass.dylib` 传到 iPhone（AirDrop / 微信文件传输助手 / iCloud）
- 打开 TrollFools → 选今日头条 → Inject dylib → 选这个文件
- 重开头条即可

---

## 常见问题

**Q: Actions 里看不到 workflow？**
A: 确认 `.github/workflows/build.yml` 上传成功了，路径不能错。

**Q: 编译失败红色叉号？**
A: 点进去看日志，最常见是 Xcode 版本问题，把 `runs-on: macos-latest` 改成 `macos-13` 或 `macos-14` 重试。

**Q: 下载的 artifact 是 zip？**
A: 对，解压后里面就是 dylib。

**Q: 免费额度够吗？**
A: GitHub 公开仓库 Actions 完全免费，私有仓库每月 2000 分钟，编译一次只用 2-3 分钟，够用。
