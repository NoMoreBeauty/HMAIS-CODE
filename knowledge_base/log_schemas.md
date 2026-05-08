# Provenance Graph & System Log Schemas

该文档定义了系统中用于安全调查的系统日志和出处图（Provenance Graph）的数据结构。

## 1. 实体类型 (Node Types)

系统图数据库包含以下几类核心实体：

- **process** (或 proc): 进程节点。代表系统中运行的进程。
  - `name`: 进程的可执行文件名（例如 `bash`, `svchost.exe`）
  - `pid`: 进程标识符
  - `command_line`: 执行该进程时使用的完整命令行参数
  - `path`: 进程可执行文件的绝对路径
  - `user`: 运行该进程的用户

- **file** (或 path): 文件节点。代表系统中的文件或目录。
  - `name`: 文件名
  - `path`: 文件的绝对路径

- **network** (或 socket, ip): 网络节点。代表远程 IP 或网络套接字。
  - `name`: 目标或源 IP 地址和端口号（例如 `10.0.0.1:80`）

## 2. 事件类型 (Edge/Relation Types)

系统图中记录了实体之间的交互事件，通常作为边（Edge）表示。边包含了事件的具体发生时间和属性。

- **EVENT_EXECUTE / SPAWN**: 进程执行事件（Process -> Process）。
  - 描述：一个父进程派生（Spawn）或执行了一个子进程。
- **EVENT_WRITE / WRITE**: 文件写入事件（Process -> File）。
  - 描述：进程向文件写入了数据。通常是下载恶意载荷或修改配置的证据。
- **EVENT_READ / READ**: 文件读取事件（Process -> File）。
  - 描述：进程读取了某个文件。常用于凭证窃取或发现行为。
- **EVENT_SENDTO**: 网络发送事件（Process -> Network）。
  - 描述：进程向远程网络节点发送数据。常用于 C2 通信或数据外发。
- **EVENT_RECVFROM**: 网络接收事件（Process -> Network）。
  - 描述：进程从网络节点接收数据。常用于下载载荷或接收 C2 指令。

## 3. 事件属性 (Event Properties)

每个事件（Edge）都会带有一些标准属性，这在调查上下文或告警中会频繁出现：

- `event_id` / `event_uuid`: 事件的全局唯一标识符，用于图数据库查询和追踪。
- `timestamp`: 事件发生的具体时间戳。
- `event_type`: 事件类型（同上文的 Edge Type）。
- `ip_context`: 仅针对网络事件，指示该事件属于“内网通信”还是“外网通信”。

## 4. 查询与分析提示
- 分析一个可疑的网络通信（`EVENT_SENDTO`）时，通常需要向上追踪发起该网络连接的 `process`，然后查询该 `process` 的命令行（`command_line`）以判断是否为合法的系统工具。
- 分析落地文件（`EVENT_WRITE`）时，应重点关注是否有后续进程将该文件执行（`EVENT_EXECUTE`），这通常对应完整的“投递 -> 执行”攻击链。
