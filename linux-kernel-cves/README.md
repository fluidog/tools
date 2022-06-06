# linux kernel CVE

# 功能

1. 通过 CVE 号，查找 CVE 对应的信息，包括 CVE 影响的 linux 内核版本范围、对应的 commit 信息及补丁。
2. 分析补丁是否已集成到指定的内核分支。


# 使用方法

1. 指定需要分析 CVE 号 (check-CVEs.txt)
2. 指定内核所在仓库的本地地址及分支。(analyze.sh 文件中的 LINUX_KERNEL_DIR 和 BRANCH字段)
3. 执行 ./analyze.sh (根据硬件等条件不同，可能需要几分钟不等)
4. 查看结果 (out-CVEs-*)


# 参考
CVE 原始数据来自: https://github.com/nluedtke/linux_kernel_cves.git, 截止到 2022/05/20, 如有更新需手动同步。