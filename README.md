# PHANTOM

PHANTOM is a C++17 network intelligence / MITM toolkit built around ARP spoofing, DNS spoofing, TLS interception, DPI, device tracking, and Wi-Fi tools.

## Build

```sh
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

## Run

```sh
sudo ./phantom -i eth0 --arp --dns --proxy --dpi --creds --scan
```

## Notes

- The project expects a single-header `nlohmann/json.hpp` under `third_party/nlohmann/`.
- Runtime-generated logs/exports are written to the `logs/` folder.
- On first launch, the CA certificate/key are generated at the repository root.
