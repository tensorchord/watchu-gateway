# WatchU

Hey, Agent! The bees are watching you!

## Usage

- SSL read/write
- Process

```bash
make build

# run the tetragon service with Unix socket
docker run -d --name tetragon --rm \
    --pid=host --cgroupns=host --privileged \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    -v /var/run/tetragon:/var/run/tetragon \
    quay.io/cilium/tetragon:v1.5.0 \
    --server-address unix:///var/run/tetragon/tetragon.sock
sudo ./bin/app
```
