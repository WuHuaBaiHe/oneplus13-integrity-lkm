# OnePlus 13 integrity LKM

这是面向 OnePlus 13（SM8750）的只读内核完整性检测模块，目标源码分支：

```text
OnePlusOSS/android_kernel_oneplus_sm8750
oneplus/sm8750_b_16.0.0_oneplus_13
Linux 6.6.118
```

## 功能

- 加载时解析 `sys_call_table`，保存系统调用表 SHA-256 基线。
- 每小时重新计算系统调用表哈希并在变化时写入内核日志。
- 通过 `kretprobe` 观察 `load_module` 的入口参数，对待加载模块镜像计算 SHA-256 并记录模块名和哈希。
- 提供只读状态节点：`/proc/op13_integrity`。

模块不修改系统调用表、模块内存、凭据、安全钩子或其他进程，也不隐藏自身或绕过模块签名。

## DDK 构建

本项目使用 [Ylarod/ddk](https://github.com/Ylarod/ddk) 的 `android15-6.6` 容器工具链。Windows/macOS 用户建议使用 Docker/DevContainer；Linux 用户也可以使用 DDK Host 模式。

### 本地准备目标源码

在项目根目录执行：

```bash
git clone --depth=1 \
  --branch oneplus/sm8750_b_16.0.0_oneplus_13 \
  https://github.com/OnePlusOSS/android_kernel_oneplus_sm8750.git kernel-src
```

然后准备与目标设备匹配的内核输出目录。至少需要目标设备实际使用的 `.config`；只使用通用 `gki_defconfig` 只能用于接口/语法验证，不能保证生成的模块与出厂内核 ABI 匹配。

该公开分支中的 `kernel/oplus_cpu` 是指向单独 vendor 源码的符号链接，而 vendor CPU 子树不在这个仓库内。Actions 在缺少链接目标时创建一个明确标注的空 Kconfig stub，只用于准备公共内核头文件和编译本模块；这不等同于完整的 OnePlus 内核构建。若你有对应 vendor 源码，应在构建前恢复真实目录。

### 使用 DDK Docker 镜像

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/build -w /build \
  ghcr.io/ylarod/ddk:android15-6.6 \
  bash -lc '\
    export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-; \
    make -C kernel-src O=/build/.kernel-out ARCH=arm64 LLVM=1 LLVM_IAS=1 modules_prepare; \
    make -C kernel-src O=/build/.kernel-out M=/build ARCH=arm64 LLVM=1 LLVM_IAS=1 modules'
```

也可以使用 DDK 自带脚本：

```bash
./ddk build android15-6.6
```

但该命令默认构建当前目录对应的标准 DDK 内核；本项目的 GitHub Actions 使用下面的显式目标源码流程，避免误用通用内核源码。

## GitHub Actions

`build.yml` 会：

1. 检出本项目。
2. 拉取固定 OnePlus 13 内核分支。
3. 使用 `ghcr.io/ylarod/ddk:android15-6.6`。
4. 使用 `KDIR` 的目标源码和 LLVM ARM64 参数构建外置模块。
5. 上传 `.ko`、构建日志、内核 commit 和配置摘要作为 artifact。

工作流不会签名、刷写或加载模块。Android 设备通常启用了 `CONFIG_MODULE_SIG`、`CONFIG_MODVERSIONS`、CFI 或其他 GKI 约束，因此生成 `.ko` 仍必须使用与你设备运行内核完全匹配的 build output、`Module.symvers`、vermagic 和签名策略。

## 关键限制

- `struct load_info` 是内核内部结构，本模块按 6.6.118 目标分支定义复制；更换分支或配置后必须重新检查布局。
- `sys_call_table` 必须能通过目标内核的 kallsyms/kprobe 机制解析；若厂商内核隐藏或移除该符号，模块会拒绝加载。
- 本地源码树没有目标设备的生成 `.config` 和 `Module.symvers`，因此当前环境只能完成源码级和构建流程级验证，不能宣称已经生成可在手机上加载的 `.ko`。

## 许可证

模块源码使用 GPL-2.0-only。目标内核源码遵循其自身许可证和版权声明。
