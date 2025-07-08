# KSMidi – Kernel‑Streaming MIDI for Windows

![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6?style=flat) ![Language: C++17](https://img.shields.io/badge/language-C++17-9B4F96?style=flat) ![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat)

*KSMidi* is a small C++17 helper that reads and writes MIDI through the Windows **Kernel Streaming (KS)** layer.  It avoids WinMM and WinRT so you only deal with the driver.

Maintained by **Mohamed Maatallah** · 2025.

---

## Repo contents

| File         | Description                                       |
| ------------ | ------------------------------------------------- |
| `KSMidi.h`   | Public header – include and use the API           |
| `KSMidi.cpp` | Implementation – add to one target and link       |
| `main.cpp`   | Simple sample: basic lib functionality demo, API benchmark|
| `test_1.cpp` | MIDI 1.0, and lib functionality tests             |
---

## Build steps (Visual Studio 2019+)

1. Create a console project.
2. Add the three files above.
3. Build and run `main.cpp`.

If you use CMake, just add the two library files to your target.

---

## API overview

Classes:

* `Api`      – static helpers to list ports and get detailed info.
* `MidiIn`   – read byte streams or UMP packets. Supports polling, threaded callback, or direct callback on the KS I/O thread.
* `MidiOut`  – write byte streams or UMP packets.

Other points:

* RAII handles; errors as `KsMidiError` exceptions.
* Works with MIDI 1.0 and MIDI 2.0 (UMP helpers included).
* Device info: name, protocol, in‑use flag.

*Note*: The library sends messages immediately.  Incoming data can be timestamped with QPC or the driver’s presentation time.

---

## Windows notes

* Opens pins in shared mode when possible.
* Raises `KsMidiError` if a pin is locked by another app.
* WinMM‑only or WinRT‑only virtual ports do not appear.

---

## Docs and roadmap

* Full API guide: [`DOCUMENTATION.md`](DOCUMENTATION.md)
* Planned: vcpkg / Conan package, virtual loopback helper, public latency tests.

---

## License

MIT.  Bug reports and pull requests are welcome.
