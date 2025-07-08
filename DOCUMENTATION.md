### The KSMidi Documentation
**Author: Mohamed Maatallah**

---

### Contents
*   [Introduction](#introduction)
*   [Getting Started](#getting-started)
*   [Error Handling](#error-handling)
*   [Probing Ports / Devices](#probing-ports--devices)
*   [MIDI Output](#midi-output)
    *   [Sending MIDI 1.0 Byte Streams](#sending-midi-10-byte-streams)
    *   [Sending MIDI 2.0 Universal MIDI Packets (UMP)](#sending-midi-20-universal-midi-packets-ump)
*   [MIDI Input](#midi-input)
    *   [Message Filtering](#message-filtering)
    *   [Queued MIDI Input (Polling)](#queued-midi-input-polling)
    *   [Queued MIDI Input with User Callback](#queued-midi-input-with-user-callback)
*   [Advanced Topics](#advanced-topics)
    *   [Direct Callback Mode](#direct-callback-mode)
    *   [MIDI 2.0 and UMP Support](#midi-20-and-ump-support)
    *   [Timestamping Modes](#timestamping-modes)
    *   [Configuration Settings](#configuration-settings)
---

### Introduction

KSMidi is a set of C++ classes (`MidiIn`, `MidiOut`, `Api`) that provides a common, high-performance API for realtime MIDI input/output on Windows. It interfaces directly with the Windows Kernel Streaming (KS) subsystem to achieve the lowest possible latency, bypassing higher-level abstractions like the Windows Multimedia (winmm) library.

KSMidi significantly simplifies the process of interacting with modern MIDI hardware and software drivers on Windows. It was designed with the following goals:

*   Object-oriented C++ design.
*   A simple, common API for both MIDI 1.0 and MIDI 2.0.
*   Full support for MIDI 2.0 Universal MIDI Packet (UMP) streams.
*   Header-only style public API (`KSMidi.h`) with a single source file (`KSMidi.cpp`) for easy inclusion in programming projects.
*   Detailed MIDI device enumeration, including availability and protocol support.
*   Flexible, high-performance input modes, including a real-time "direct callback" path for latency-critical applications.
*   Lock-free, single-producer single-consumer (SPSC) queues for thread-safe message passing.

MIDI input and output functionality are separated into two primary classes, `MidiIn` and `MidiOut`. Each class instance supports a single MIDI connection. KSMidi does not provide its own timing functionality for output; messages sent via `MidiOut` are dispatched to the driver immediately. Input messages are timestamped with high precision (in seconds via a `double`), with the timestamping source being user-configurable. MIDI 1.0 data is passed to the user as raw bytes using an `std::vector<BYTE>`, while MIDI 2.0 data uses a dedicated `ksmidi::ump::UmpMessage` struct.

### Getting Started

The first step when using KSMidi is to create an instance of the `MidiIn` or `MidiOut` class. KSMidi uses C++ exceptions to report errors during instantiation and port operations, necessitating `try/catch` blocks around many member functions. A `KsMidiError` can be thrown during object construction or when opening a port.

The following code example demonstrates default object construction and destruction:

```cpp
#include "KSMidi.h"
#include <iostream>

int main() {
  try {
    // Instantiate a MidiIn object to prepare for input.
    ksmidi::MidiIn midiin;
    std::cout << "KSMidiIn object created successfully." << std::endl;

    // Instantiate a MidiOut object to prepare for output.
    ksmidi::MidiOut midiout;
    std::cout << "KSMidiOut object created successfully." << std::endl;

  } catch (const ksmidi::KsMidiError &error) {
    // Handle any exceptions during construction.
    std::cerr << "Error: " << error.what() << std::endl;
    return 1;
  }

  // Objects are automatically cleaned up when they go out of scope.
  return 0;
}
```
This example does not demonstrate any real functionality. However, all uses of KSMidi must begin with object construction and must end with class destruction, which handles the release of all system resources.

### Error Handling

KSMidi uses a C++ exception class called `KsMidiError`, which is declared in `KSMidi.h` and inherits from `std::runtime_error`. Many KSMidi methods can "throw" a `KsMidiError`, most typically if a driver error occurs, a port is unavailable, or an invalid function argument is specified.

The `KsMidiError` class provides two methods for inspection:
*   `what()`: Returns a `const char*` containing a descriptive error message.
*   `code()`: Returns the Windows `HRESULT` associated with the error, for detailed diagnosis.

For non-fatal runtime errors that occur during active streaming (e.g., a device is unplugged), `MidiIn` provides a separate `setErrorCallback` mechanism to avoid throwing exceptions from its internal I/O thread.

### Probing Ports / Devices

A client application must query the available MIDI ports to determine which to open. The static `ksmidi::Api` class provides the necessary functions for this. Unlike older APIs that only provide a port name, KSMidi returns a `DeviceInfo` struct with detailed information for each port.

```cpp
// midiprobe.cpp
#include <iostream>
#include <string>
#include "KSMidi.h"

int main() {
  try {
    // --- Probe Input Ports ---
    unsigned int nInPorts = ksmidi::Api::getPortCountIn();
    std::cout << "\nThere are " << nInPorts << " MIDI input sources available.\n";
    for (unsigned int i = 0; i < nInPorts; ++i) {
      ksmidi::DeviceInfo info = ksmidi::Api::getPortInfoIn(i);
      std::cout << "  Input Port #" << i << ": " << info.name << "\n";
      std::cout << "    Available: " << (info.isAvailable ? "Yes" : "No") << "\n";
      std::cout << "    MIDI 2.0 (UMP): " << (info.supportsMidi2 ? "Yes" : "No") << "\n";
    }

    // --- Probe Output Ports ---
    unsigned int nOutPorts = ksmidi::Api::getPortCountOut();
    std::cout << "\nThere are " << nOutPorts << " MIDI output ports available.\n";
    for (unsigned int i = 0; i < nOutPorts; ++i) {
      ksmidi::DeviceInfo info = ksmidi::Api::getPortInfoOut(i);
      std::cout << "  Output Port #" << i << ": " << info.name << "\n";
      std::cout << "    Available: " << (info.isAvailable ? "Yes" : "No") << "\n";
      std::cout << "    MIDI 2.0 (UMP): " << (info.supportsMidi2 ? "Yes" : "No") << "\n";
    }
    std::cout << std::endl;

  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
    return 1;
  }
  return 0;
}
```
Note that port enumeration is dynamic. If a user plugs in or unplugs a device, the port list will change. It is recommended to verify port information immediately before opening a connection.

### MIDI Output

The `MidiOut` class provides simple functionality to immediately send messages over a MIDI connection. It supports both traditional MIDI 1.0 byte streams and modern MIDI 2.0 Universal MIDI Packets.

#### Sending MIDI 1.0 Byte Streams

For devices that do not support MIDI 2.0, messages are sent as a vector of bytes.

```cpp
// midiout_1.0.cpp
#include "KSMidi.h"
#include <vector>
#include <iostream>
#include <windows.h>  // For Sleep()

int main() {
  ksmidi::MidiOut midiout;
  std::vector<BYTE> message;

  try {
    if (ksmidi::Api::getPortCountOut() == 0) {
      std::cout << "No output ports available!\n";
      return 0;
    }
    midiout.openPort(0); // Open the first available port.

    if (midiout.isUmpStream()) {
      std::cout << "Port is MIDI 2.0; use UMP sending methods.\n";
      return 0;
    }

    // Note On: 144 (0x90), 60, 127
    message = { 0x90, 60, 127 };
    midiout.sendMessage(message);

    // Platform-dependent sleep
    Sleep(500);

    // Note Off: 128 (0x80), 60, 0
    message = { 0x80, 60, 0 };
    midiout.sendMessage(message);

  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  // midiout destructor automatically calls closePort().
  return 0;
}
```

#### Sending MIDI 2.0 Universal MIDI Packets (UMP)

If `isUmpStream()` returns `true`, the port is a MIDI 2.0 endpoint. Messages should be sent using the `ksmidi::ump::UmpMessage` struct. Helper functions are provided to construct these packets.

```cpp
// midiout_2.0.cpp
#include "KSMidi.h"
#include <iostream>
#include <windows.h>  // For Sleep()

int main() {
  ksmidi::MidiOut midiout;
  try {
    if (ksmidi::Api::getPortCountOut() == 0) return 0;

    midiout.openPort(0); // Open a port (assuming it's a UMP port).

    if (!midiout.isUmpStream()) {
      std::cout << "Port is MIDI 1.0.\n";
      return 0;
    }

    // Create and send a MIDI 2.0 Note On packet.
    // Group 0, Channel 0, Note 60, Velocity 65535 (max)
    ksmidi::ump::UmpMessage noteOn = ksmidi::ump::makeNoteOn(0, 0, 60, 65535);
    midiout.sendMessage(noteOn);

    Sleep(500);

    // Create and send a MIDI 2.0 Note Off packet.
    ksmidi::ump::UmpMessage noteOff = ksmidi::ump::makeNoteOff(0, 0, 60);
    midiout.sendMessage(noteOff);

  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  return 0;
}
```

### MIDI Input

The `MidiIn` class uses an internal, high-priority thread to receive incoming MIDI messages. These messages can be retrieved in two primary ways: by polling a queue or by registering a callback function. A third, advanced "direct callback" mode is also available for minimal latency.

#### Message Filtering

The `MidiIn::ignoreTypes()` function can be used to specify that certain MIDI 1.0 message types (SysEx, Time, or Active Sense) be ignored by the internal parser. By default, SysEx, Time, and Active Sense messages are ignored (see `MidiIn::Settings` defaults).

**Important:** The `ignoreTypes()` method must be called **before** opening the port. Attempting to change filter settings while a port is open will throw a `KsMidiError` with code `E_ACCESSDENIED`.

```cpp
// Example: Configure message filtering before opening port
ksmidi::MidiIn midiin;

// Enable SysEx messages, disable timing and active sensing
midiin.ignoreTypes(false, true, true);  // Must be called before openPort()

// Now open the port with the configured filters
midiin.openPort(0);
```

#### Queued MIDI Input (Polling)

The `pop_message()` and `pop_ump_message()` functions do not block. If a message is available in the internal queue, it is returned within a `std::optional`. If no message is available, the function returns an empty `std::optional`. This is the simplest method for retrieving MIDI data.

```cpp
// qmidiin.cpp
#include <iostream>
#include <vector>
#include <csignal>
#include <windows.h>  // For Sleep()
#include "KSMidi.h"

static bool done = false;
void finish(int ignore){ done = true; }

int main() {
  ksmidi::MidiIn midiin;
  (void) signal(SIGINT, finish);

  try {
    if (ksmidi::Api::getPortCountIn() == 0) {
      std::cout << "No input ports available!\n";
      return 0;
    }
    midiin.openPort(0);

    std::cout << "Reading MIDI from port ... quit with Ctrl-C.\n";
    while (!done) {
      if (midiin.isUmpStream()) {
        if (auto msg = midiin.pop_ump_message()) {
          std::cout << "UMP Stamp: " << msg->timestamp << " Word0: 0x" 
                    << std::hex << msg->words[0] << std::dec << std::endl;
        }
      } else {
        if (auto msg = midiin.pop_message()) {
          std::cout << "MIDI 1.0 Stamp: " << msg->timestamp << " Bytes: ";
          for(const auto& byte : msg->bytes) std::cout << (int)byte << " ";
          std::cout << std::endl;
        }
      }
      Sleep(1); // Prevent high CPU usage.
    }
  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  return 0;
}
```

#### Queued MIDI Input with User Callback

A user-provided callback function can be registered via `setCallback()` or `setUmpCallback()`. When this is done, a dedicated poller thread is created which safely invokes the callback whenever a new message arrives in the queue. This isolates the user's code from the real-time I/O thread.

```cpp
// cmidiin.cpp
#include <iostream>
#include <vector>
#include "KSMidi.h"

void my_midi1_callback(const ksmidi::MidiMessage& message) {
  std::cout << "Stamp: " << message.timestamp << " Bytes: ";
  for (const auto& byte : message.bytes)
    std::cout << (int)byte << " ";
  std::cout << std::endl;
}

void my_ump_callback(const ksmidi::ump::UmpMessage& message) {
  std::cout << "UMP Stamp: " << message.timestamp 
            << " Size: " << (int)message.size_in_words << " words" << std::endl;
}

int main() {
  ksmidi::MidiIn midiin;
  try {
    if (ksmidi::Api::getPortCountIn() == 0) {
      std::cout << "No input ports available!\n";
      return 0;
    }
    midiin.openPort(0);

    // Set appropriate callback based on stream type
    if (midiin.isUmpStream()) {
        midiin.setUmpCallback(my_ump_callback);
    } else {
        midiin.setCallback(my_midi1_callback);
    }

    std::cout << "\nReading MIDI input ... press <enter> to quit.\n";
    char input;
    std::cin.get(input);

  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  return 0;
}
```

### Advanced Topics

#### Direct Callback Mode

For applications requiring the absolute minimum latency, KSMidi provides a "direct callback" mode. When enabled, the user's callback function is invoked **directly from the high-priority kernel streaming I/O thread**. This bypasses all internal queueing and secondary threads.

**Warning:** The callback function in this mode **must be extremely fast, non-blocking, and thread-safe**. Any blocking operations (file I/O, mutex contention, memory allocation) will stall the MIDI input stream and can lead to data loss or system instability.

```cpp
// direct_callback.cpp
#include "KSMidi.h"
#include <iostream>
#include <cstdio>

// This callback runs on a high-priority, real-time thread.
// It must be non-blocking and very fast.
void my_direct_callback(const BYTE* data, size_t size, double timestamp, void* userData) {
    // A simple, fast operation:
    printf("Direct CB - TS: %f, Size: %zu\n", timestamp, size);
}

int main() {
  ksmidi::MidiIn midiin;
  try {
    midiin.openPort(0); // Open port first

    // Set the direct callback.
    midiin.setDirectCallback(my_direct_callback, nullptr);

    std::cout << "\nListening with direct callback ... press <enter> to quit.\n";
    std::cin.get();
    midiin.cancelDirectCallback(); // Important to unregister
    midiin.closePort();

  } catch (const ksmidi::KsMidiError &error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  return 0;
}
```

#### MIDI 2.0 and UMP Support

KSMidi provides a first-class API for MIDI 2.0.
*   **Detection:** `Api::getPortInfo...()` and `MidiIn/Out::isUmpStream()` report if a device uses the UMP protocol.
*   **Sending:** `MidiOut::sendMessage()` is overloaded to accept a `ksmidi::ump::UmpMessage`. The `ksmidi::ump` namespace contains helper functions like `makeNoteOn`, `makeNoteOff`, `makeControlChange`, `makeProgramChange`, and `makePitchBend` to construct valid packets.
*   **Receiving:** `MidiIn` provides a separate API for UMP streams. Use `pop_ump_message()` for polling or `setUmpCallback()` for callback-based input. This ensures type safety and avoids confusion with MIDI 1.0 byte streams.
*   **Message Types:** All 16 UMP message types are supported, including Utility, System, MIDI 1.0/2.0 Channel Voice, Data messages, and Stream messages.

#### Timestamping Modes

The timestamp associated with incoming MIDI messages can be configured via `MidiIn::Settings::timestampMode`.

*   `TimestampMode::None`: No timestamping is performed (timestamp is always 0.0). This offers the highest performance if timing is not required.
*   `TimestampMode::QPC` (Default): Uses `QueryPerformanceCounter` at the moment the data is processed by the library. This provides a high-resolution, low-overhead timestamp.
*   `TimestampMode::Driver`: Uses the `PresentationTime` provided by the kernel driver itself. This is potentially the most accurate timestamp, as it is closest to the hardware event.

#### Configuration Settings

The `MidiIn::Settings` struct provides fine-grained control over input behavior:

```cpp
ksmidi::MidiIn::Settings settings;
settings.bufferSize = 512;        // Size of each kernel buffer
settings.bufferCount = 4;         // Number of buffers (min 2, max 64)
settings.sysexChunkSize = 1024;   // Max size before SysEx chunking
settings.ignoreSysex = true;      // Ignore SysEx messages (default)
settings.ignoreTime = true;       // Ignore Timing messages (default)
settings.ignoreSense = true;      // Ignore Active Sensing (default)
settings.timestampMode = ksmidi::MidiIn::TimestampMode::QPC;  // Default
settings.messageQueueSize = 256;  // Must be power of 2
settings.umpMessageQueueSize = 256;  // Must be power of 2
settings.errorQueueSize = 16;     // Must be power of 2

midiin.openPort(0, settings);
```

**Note:** All queue sizes must be powers of 2. The library will throw an exception if this requirement is not met.




