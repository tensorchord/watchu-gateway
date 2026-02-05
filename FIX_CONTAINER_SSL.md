# Container SSL Traffic Capture Fix

## 问题描述

watchu collector 在捕获容器的 SSL/TLS 流量时存在可靠性问题，表现为：
- 某些容器的 HTTPS 请求无法被捕获
- 行为具有随机性，与时序相关
- 在 collector 启动后创建的容器尤其容易失败

## 根本原因

经过深入调查发现两个关键 bug：

1. **永久性跳过缓存**：`procSkip` 缓存永久性地标记没有 libssl 的进程
2. **没有重新扫描机制**：进程在被扫描后加载 SSL 库不会被检测到

### 问题机制

```
时间轴示例：
T=0s:  容器启动，node 进程创建（还未加载 libssl）
T=2s:  collector 扫描该进程，/proc/{pid}/maps 中没有 libssl
       → 进程被加入 procSkip 缓存
T=5s:  node 进程处理第一个 HTTPS 请求，动态加载 libssl.so
T=7s:  collector 再次扫描，检查 procSkip，发现该进程已被标记
       → 跳过该进程，永远不会重新检查
结果:   该容器的所有 SSL 流量都无法被捕获
```

## 修复方案

### 核心改动

1. **添加过期时间常量**
   ```go
   const PROC_SKIP_EXPIRE_TIME = time.Minute * 1  // 1分钟后过期
   ```

2. **为 skip 条目添加时间戳**
   ```go
   type procSkipEntry struct {
       timestamp time.Time
   }
   ```

3. **在扫描时检查过期**
   ```go
   if skipEntry, ok := cld.procSkip[proc]; ok {
       if time.Since(skipEntry.timestamp) < PROC_SKIP_EXPIRE_TIME {
           // 仍然有效，保持跳过状态
           newProcSkip[proc] = skipEntry
           return
       }
       // 已过期，重新扫描
   }
   ```

4. **定期清理过期条目**
   ```go
   func (cld *ContainerLibsDetector) cleanupExpiredSkips() {
       // 每隔 PROC_SKIP_EXPIRE_TIME 运行一次
       // 删除所有过期的 skip 条目
   }
   ```

### 改进的日志

- 降低常规操作的日志级别到 DEBUG
- 为 SSL 库发现添加 INFO 级别日志
- 添加 skip 条目过期的调试日志

## 效果

修复后的行为：
```
T=0s:  容器启动，node 进程创建
T=2s:  collector 扫描，没有 libssl，添加到 skip（带时间戳）
T=5s:  node 加载 libssl（处理 HTTPS 请求）
T=7s:  collector 扫描，skip 条目仍在有效期内，跳过
...
T=62s: collector 扫描，skip 条目已过期（>60s）
       → 重新扫描进程
       → 发现 libssl.so
       → 附加 SSL uprobes
       ✓ 开始捕获该容器的 SSL 流量
```

**最坏情况延迟**：60 秒（skip 过期时间）
**典型情况**：如果进程在被扫描前就加载了 SSL，会立即被检测到

## 测试方法

### 自动化测试脚本

```bash
./test-container-ssl-fix.sh
```

该脚本会：
1. 创建 5 个测试容器
2. 每个容器每 5 秒发送一次 HTTPS 请求
3. 等待 70 秒（覆盖 skip 过期时间）
4. 检查 collector 日志验证流量捕获

### 手动测试

1. 重新构建 collector：
   ```bash
   cd collector
   go build .
   ```

2. 重启 collector 容器：
   ```bash
   docker restart watchu-collector
   ```

3. 创建测试容器：
   ```bash
   docker run -d --name test-manual node:18 sh -c '
   cat > test.js << EOF
   const https = require("https");
   setInterval(() => {
       https.get("https://httpbin.org/get?test=manual", (res) => {
           console.log("Status:", res.statusCode);
       });
   }, 5000);
   EOF
   node test.js
   '
   ```

4. 等待 ~70 秒后检查日志：
   ```bash
   docker logs watchu-collector 2>&1 | grep -i "found SSL library"
   docker logs watchu-collector 2>&1 | grep "test=manual"
   ```

## 配置选项

如果需要调整过期时间，修改 `collector/internal/container/dynamic.go`：

```go
const PROC_SKIP_EXPIRE_TIME = time.Minute * 2  // 改为 2 分钟
```

权衡：
- **更短的过期时间**（如 30s）：更快检测到新加载的 SSL，但增加 CPU 开销
- **更长的过期时间**（如 5m）：降低 CPU 开销，但延迟检测新的 SSL

推荐：**1 分钟**（当前设置）在性能和响应性之间取得良好平衡

## 相关文件

- `collector/internal/container/dynamic.go` - 主要修复代码
- `test-container-ssl-fix.sh` - 自动化测试脚本
- `FIX_CONTAINER_SSL.md` - 本文档

## 提交信息

```
git log --oneline -1
815b7b3 fix: add expiration mechanism for procSkip cache to reliably capture container SSL traffic
```

## 后续优化建议

1. **eBPF 事件监听**：使用 eBPF 监听 mmap 事件，实时检测 libssl 加载
2. **可配置的过期时间**：通过环境变量或配置文件设置 `PROC_SKIP_EXPIRE_TIME`
3. **指标暴露**：添加 Prometheus 指标跟踪 skip 缓存命中率和过期清理
