# OnePlus 13 integrity LKM

在 OnePlus 13 ARM64 Linux 6.6.118 构建环境中编译固定版本的 Ace 6 Ultra `oplus_kernel_security_check.c`。实际编译文件 `op13_integrity.c` 与固定上游文件逐字节一致，不包含自行添加的功能或安全修复。

## 来源和范围

原版仓库：OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_mt6993，分支 `oneplus/mt6993_b_16.0_ace_6_ultra`，固定提交 `2cc7f4606b65a9ede42030ee82614dd845b665a1`。

原文件为 `vendor/oplus/kernel/secureguard/gki2.0/rootguard_new/oplus_kernel_security_check.c`。未经改动的参考副本保存在 [upstream/oplus_kernel_security_check.c](upstream/oplus_kernel_security_check.c)，SHA-256 为 `47f6f8386f700220b609a1ea9a3f47a8fa2bddeeaeaa15645f90abe8b5319720`。

目标仓库：OnePlusOSS/android_kernel_oneplus_sm8750，分支 `oneplus/sm8750_b_16.0.0_oneplus_13`，Linux 6.6.118。本项目不提供原版配套的用户空间 `oplus_kohashpro` 服务。

## 原版行为

- 初始 boot_stage=0。通过 inte_status 写入二进制整数 1 后才启用模块检查和周期系统调用表检查；写其它值不会复位。此前的模块不补查。
- 初始化时保存 syscall 指针数组 SHA-256 基线；初始化一小时后首次工作，每次完成后一小时重新排程。持续异常每次都记事件。
- kretprobe 在 load_module 入口同步哈希整个 info->hdr/info->len，4096 字节分块，每次更新后检查耗时是否大于 100 ms。超时/哈希失败/模块名提取失败只打印日志，不记录模块异常。
- 模块名自动追加 .ko，与白名单比较；仅未知或哈希不匹配模块记异常，两类均只记录名称。匹配模块不加入异常队列。
- 模块和 syscall 各自保存 10 条 FIFO，满后删最旧，不去重。读取不消费事件。syscall 异常格式为 Unix 毫秒时间戳加 `:true`，不产生恢复事件。
- 不阻止模块加载；失败的加载尝试也可能产生事件。kretprobe maxactive=100，保留原版入口返回值和实例占用语义。

## proc ABI

仅三个节点，没有 `/proc/op13_integrity` 或额外文本命令。

| 节点 | 模式/所属 | 读 | 写 |
|---|---|---|---|
| inte_ko | 0664 root:root | 异常模块或用户事件，按旧到新逐行输出 | 二进制批量白名单或用户事件 |
| inte_systbl | 0664 root:root | `毫秒时间戳:true`，逐行输出 | 原版条件 debug 控制 |
| inte_status | 0660 root:root | 无读回调 | 二进制 int32，只有 1 生效 |

inte_ko 批量白名单（ARM64 本机端序，小端）：

```c
u32 entry_count;              // 1..1000，限制单次批量，不限制总表容量
struct hash_entry {
    char filename[40];       // 最多保存39字节；'-'规范化为'_'
    unsigned char hash[32];  // 原始SHA-256字节，不是64字符hex
} entries[entry_count];      // 每项72字节
```

同名条目首次插入生效，后续写入跳过，不更新哈希。接受尾部多余字节；内存不足可能已部分插入，不回滚。

inte_ko 用户事件：`u32 10000 + int32 正长度L + L字节事件内容`。补 NUL，嵌入 NUL 截断；加入同一模块事件 FIFO。10000 是输入协议分支标记，不是通用异常类别。

inte_ko 写回调要求线程 comm=`oplus_kohashpro` 且 raw euid=1000；root 也会被此校验拒绝。inte_status 和启用 debug 时的 inte_systbl 写要求 euid=0或1000。还必须通过 proc DAC 与设备 SELinux，euid=1000 本身不获得 root:root 节点的写权限。

inte_status 正常写入为4字节二进制整数；`echo 1` 不是协议正确的使用方式。原版在 count<4 时仅打印错误，仍尝试 copy_from_user 4字节；本项目原样保留该异常路径。

仅当 CONFIG_DYNAMIC_DEBUG、CONFIG_DEBUG_OBJECTS、CONFIG_DEBUG_KMEMLEAK 都启用时，inte_systbl 的首字节 ASCII `0` 检查真实表、`1` 修改复制数组第0项模拟异常（不修改真实 syscall 表）、`2` 清两事件队列。debug关闭时写操作空操作并返回长度。debug操作不受boot闸门限制。

## 源码一致性

实际编译文件和 upstream 参考副本均为固定上游文件原始字节，Git blob 为 `692ddfcda0482100f6bf70f8ee254775da56e7c2`。未添加头文件、ELF校验、短写入拒绝、初始化/卸载重排或额外日志；原版的日志、错误返回和异常路径均保留。

原版先发布proc，随后注册探针、创建syscall基线，最后hash_init；卸载在释放状态后才删除proc。这些并发窗口、原版ELF边界检查缺失、状态短写入以及debug共享缓冲行为均未修复。原版的源码缺陷也属于本项目保持零修改的范围。

字节一致只证明源码没有差异。OnePlus 13 与 Ace 6 Ultra 的内核配置、符号、CPU/密码实现、调度和SELinux环境不同，实际运行时间、哈希基线、事件和加载结果不能由源码一致推导为相同。配套用户空间服务和出厂配置未复制，实机结果须独立验证。

## GitHub Actions 构建

编译由 [.github/workflows/build.yml](.github/workflows/build.yml) 完成，使用 [Ylarod/ddk](https://github.com/Ylarod/ddk) 的 `ghcr.io/ylarod/ddk:android15-6.6`，目标为上述 OnePlus 13 公共源码。Actions同时验证普通和debug三项开启配置，分别上传模块和配置。

公共源码缺少独立 vendor 子树，流程对悬空链接和缺失 Kconfig 创建有界 stub；它只准备公共头文件，不是完整厂商内核构建。缺少目标 Module.symvers 时 KBUILD_MODPOST_WARN=1 只允许源码编译检查继续，不证明设备符号版本或签名匹配。

加载须符合设备实际 config、Module.symvers、vermagic、CFI和签名要求；新版本运行结果须单独验证，旧版本测试与 .ko 字符串检查均不能证明本版本协议已实测。

## 许可

保留原文件作者注释和 GPL 模块声明；内核及工具链遵循各自许可。
