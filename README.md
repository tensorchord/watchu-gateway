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

# run with MCP StdIO & SSL & Tetragon, exporting to the gateway
sudo ./collector/bin/app -tetragon-path unix:///var/run/tetragon/tetragon.sock --export=http://localhost:8080
# or run without Tetragon
sudo ./collector/bin/app
```

If you want to build the collector docker image and run it as a container:

```bash
docker buildx build -t watchu-collector --load .
docker run --rm \
    --cap-add=CAP_SYS_ADMIN \
    --cap-add=CAP_SYS_PTRACE \
    --cap-add=CAP_BPF \
    --cap-add=CAP_PERFMON \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    --pid=host \
    --security-opt apparmor=unconfined \
    watchu-collector
```

## Gateway & Frontend Usage

```bash
cd gateway && make compose-up
```

The gateway will be available at `http://localhost:8080`, the frontend will be available at `http://localhost:5173`.
