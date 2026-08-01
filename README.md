# PHANTOM

PHANTOM is a C++17 network intelligence / MITM toolkit built around ARP spoofing, DNS spoofing, TLS interception, DPI, device tracking, and Wi-Fi tools.

## Build

### Linux (Parrot OS, Debian, Ubuntu, etc.)

```sh
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

Do **not** pass `-G "Visual Studio 17 2022"` on Linux — Visual Studio generators only exist when CMake itself runs on Windows with Visual Studio installed, so `cmake` will fail with `Could not create named generator`. On Linux, just run `cmake ..` with no `-G` flag; it defaults to Unix Makefiles (or pass `-G Ninja` if you have Ninja installed and prefer it).

### Windows (native, run from a Visual Studio Developer Command Prompt or PowerShell — not from Linux/WSL bash)

```powershell
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR=C:/OpenSSL-Win64
cmake --build . --config Release
```

Note the multi-line continuation character differs by shell: PowerShell/cmd use `` ` `` or `^`, while bash uses `\`. Mixing them (e.g. pasting a `^` line continuation into a bash prompt) causes bash to treat the rest of the command as a separate, invalid command.

## Run

```sh
sudo ./phantom -i eth0 --arp --dns --proxy --dpi --creds --scan
```

## Notes

- The project expects a single-header `nlohmann/json.hpp` under `third_party/nlohmann/`.
- Runtime-generated logs/exports are written to the `logs/` folder.
- On first launch, the CA certificate/key are generated at the repository root.
