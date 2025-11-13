# WatchU

Hey, Agent! :honeybee: The bees are watching you! :honeybee:

## Collector Usage

- SSL read/write
- MCP StdIO
- Process

```bash
cd collector && make build

# run the tetragon service with Unix socket
docker run -d --name tetragon --rm \
    --pid=host --cgroupns=host --privileged \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    -v /var/run/tetragon:/var/run/tetragon \
    quay.io/cilium/tetragon:v1.6.0 \
    --server-address unix:///var/run/tetragon/tetragon.sock

# run with MCP StdIO & SSL & Tetragon
sudo ./collector/bin/app -tetragon-socket unix:///var/run/tetragon/tetragon.sock
# or run without Tetragon
sudo ./collector/bin/app
```

## Gateway Usage

```bash
cd gateway && make compose-up
```

The gateway will be available at `http://localhost:8080`.

## Frontend Usage

```bash
cd frontend && npm install && VITE_API_BASE_URL="http://localhost:8080/api/v1" npm run dev
```

The frontend will be available at `http://localhost:5173`.
