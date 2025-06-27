# KSMidi

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge" alt="Platform: Windows">
  <img src="https://img.shields.io/badge/language-C++17-9B4F96?style=for-the-badge" alt="Language: C++17">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License: MIT">
</p>

**KSMidi** is a modern C++ library for high-performance, low-latency MIDI I/O on Windows. It interfaces directly with device drivers via **Windows Kernel Streaming (KS)**, bypassing higher-level abstractions like WinMM to provide a fast and direct path for time-critical audio applications.

The library is designed for simplicity and performance, offering a clean API that is easy to integrate into any project with just two files: `KSMidi.h` and `KSMidi.cpp`.

## Key Features

*   **Direct Kernel Streaming:** Achieves minimal latency by avoiding intermediate software layers.
*   **Modern C++ API:** A clean, exception-safe, and resource-managing (RAII) interface.
*   **Dual Input Models:**
    *   **Callback API:** Asynchronous, real-time message handling on a dedicated thread.
    *   **Polling API:** Manually retrieve messages from a lock-free queue on your own thread.
*   **High-Performance Internals:** Uses overlapped I/O and a lock-free SPSC queue for thread-safe, efficient message passing.
*   **Robust & Self-Contained:** No external dependencies beyond the Windows SDK. Includes clear error reporting and device management.

## Quick Start Guide

### 1. Integration

1.  Add `KSMidi.h` and `KSMidi.cpp` to your C++ project.
2.  Link against `setupapi.lib` and `ksuser.lib`.
    *   In Visual Studio: `Project Properties` > `Linker` > `Input` > `Additional Dependencies`.

### 2. List Available MIDI Ports

Use the static `Api` class to discover connected MIDI devices.

```cpp
#include "KSMidi.h"
#include <iostream>

void list_ports() {
    try {
        std::cout << "Input Ports:\n";
        for (unsigned int i = 0; i < ksmidi::Api::getPortCountIn(); ++i) {
            auto info = ksmidi::Api::getPortInfoIn(i);
            std::cout << "  [" << i << "] " << info.name 
                      << (info.isAvailable ? "" : " (In Use)") << std::endl;
        }

        std::cout << "\nOutput Ports:\n";
        for (unsigned int i = 0; i < ksmidi::Api::getPortCountOut(); ++i) {
            auto info = ksmidi::Api::getPortInfoOut(i);
            std::cout << "  [" << i << "] " << info.name
                      << (info.isAvailable ? "" : " (In Use)") << std::endl;
        }
    } catch (const ksmidi::KsMidiError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

### 3. Send MIDI Messages

Instantiate `MidiOut`, open a port, and send messages.

```cpp
#include "KSMidi.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>

void play_note(unsigned int portId) {
    ksmidi::MidiOut midiOut;
    try {
        midiOut.openPort(portId);
        std::cout << "Port " << portId << " opened. Sending a note...\n";

        // Note On: Channel 1, Middle C, Velocity 100
        midiOut.sendMessage({ 0x90, 60, 100 });
        
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Note Off: Channel 1, Middle C
        midiOut.sendMessage({ 0x80, 60, 0 });

        std::cout << "Note sent. Port will be closed.\n";
    } catch (const ksmidi::KsMidiError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

### 4. Receive MIDI Messages

Instantiate `MidiIn` and use the callback system for real-time monitoring.

```cpp
#include "KSMidi.h"
#include <iostream>
#include <chrono>
#include <thread>

// Callback function to print messages as they arrive
void print_message(const ksmidi::MidiMessage& msg) {
    std::cout << msg.source << " | ";
    for (const auto& byte : msg.bytes) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

void monitor_input(unsigned int portId) {
    ksmidi::MidiIn midiIn;
    try {
        // Set a callback for handling runtime errors (e.g., device disconnect)
        midiIn.setErrorCallback([](const ksmidi::KsMidiError& e) {
            std::cerr << "Runtime Error: " << e.what() << std::endl;
        });

        // Set the message callback
        midiIn.setCallback(print_message);

        // Open the port, which starts the listener thread
        midiIn.openPort(portId);
        std::cout << "Monitoring port " << portId << ". Press Enter to stop.\n";

        std::cin.get();
        
    } catch (const ksmidi::KsMidiError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## Documentation

For further reading please refer here:

*   **[Documentation](DOCUMENTATION.md)**


## Building the Test Application

The included `main.cpp` provides an interactive command-line tool for exploring all library features.

**To build with Visual Studio:**
1.  Create a new C++ "Console App" project.
2.  Add `KSMidi.h`, `KSMidi.cpp`, and `main.cpp` to the project.
3.  Set the project to link `setupapi.lib` and `ksuser.lib`.
4.  Build and run.

## License

This project is licensed under the MIT License.


