# KSMidi API Documentation

This document provides a detailed overview of the KSMidi library's features, classes, and methods, reflecting its high-performance, low-latency design.

## Table of Contents
1.  [Core Concepts](#core-concepts)
    *   [MidiMessage](#midimessage)
    *   [DeviceInfo](#deviceinfo)
    *   [KsMidiError](#ksmidierror)
2.  [API Reference](#api-reference)
    *   [ksmidi::Api](#ksmidiapi-static-class)
    *   [ksmidi::MidiOut](#ksmidimidiout)
    *   [ksmidi::MidiIn](#ksmidimidiin)
3.  [Advanced Topics](#advanced-topics)
    *   [Callback Modes: Direct vs. Queued](#callback-modes-direct-vs-queued)
    *   [Threading Model & Performance](#threading-model--performance)
    *   [SysEx Message Handling](#sysex-message-handling)
    *   [Error Handling](#error-handling)

---

## Core Concepts

These are the fundamental data structures used throughout the KSMidi library.

### `MidiMessage`
A struct representing a single, complete MIDI message or a chunk of a larger SysEx message.

```cpp
struct MidiMessage {
    double timestamp;        // High-resolution timestamp in seconds (QPC based)
    std::vector<BYTE> bytes; // The raw bytes of the MIDI message
    std::string source;      // The friendly name of the port that sent the message
    bool isSysExChunk;       // True if this is an incomplete part of a SysEx message
};
```

### `DeviceInfo`
A struct containing detailed information about a single MIDI input or output port.

```cpp
struct DeviceInfo {
    unsigned int id;         // The library-assigned port ID number (e.g., 0, 1, 2...)
    std::string name;        // The user-friendly name of the device
    std::wstring path;       // The internal Windows device path (for opening the device)
    DWORD pinId;             // The Kernel Streaming pin ID for this port
    bool isAvailable;        // True if the port is not currently in use
};
```

### `KsMidiError`
An exception class for all library errors, inheriting from `std::runtime_error`.

-   Use `.what()` to get a descriptive error message.
-   Use `.code()` to get the associated Windows `HRESULT` for further diagnosis.

```cpp
try {
    // KSMidi operation
} catch (const ksmidi::KsMidiError& e) {
    std::cerr << "KSMidi Error: " << e.what() << std::endl;
    std::cerr << "HRESULT Code: 0x" << std::hex << e.code() << std::endl;
}
```

---

## API Reference

### `ksmidi::Api` (Static Class)
A static-only class for querying available MIDI ports.

**`static unsigned int getPortCountIn()`**
-   Returns the number of available MIDI input ports.

**`static unsigned int getPortCountOut()`**
-   Returns the number of available MIDI output ports.

**`static DeviceInfo getPortInfoIn(unsigned int portNumber)`**
-   **`portNumber`**: The ID of the input port (from `0` to `getPortCountIn() - 1`).
-   Returns a `DeviceInfo` struct for the specified input port.
-   Throws a `KsMidiError` if `portNumber` is invalid.

**`static DeviceInfo getPortInfoOut(unsigned int portNumber)`**
-   **`portNumber`**: The ID of the output port (from `0` to `getPortCountOut() - 1`).
-   Returns a `DeviceInfo` struct for the specified output port.
-   Throws a `KsMidiError` if `portNumber` is invalid.

### `ksmidi::MidiOut`
A class for sending MIDI messages to an output port. It uses asynchronous I/O for non-blocking, high-throughput operation.

**`MidiOut()`**
-   Default constructor.

**`~MidiOut()`**
-   Destructor. Automatically calls `closePort()` to release system resources.

**`void openPort(unsigned int portNumber, const Settings& settings = {})`**
-   Opens a connection to the specified MIDI output port.
-   **`portNumber`**: The ID of the output port to open.
-   **`settings`**: An optional `Settings` struct to configure port behavior.
-   Throws a `KsMidiError` on failure (e.g., port not available, invalid ID).

**`MidiOut::Settings` Struct**
```cpp
struct Settings {
    PinPriority priority = PinPriority::NORMAL;  
    size_t maxMessageSize = 65536;             
    unsigned int asyncBuffers = 4;            
};
```
- **`priority`**: Sets the kernel scheduling priority for the MIDI data stream. Results may differ from system to system.
  - **`PinPriority::NORMAL` (Default)**: Balanced performance for general use.
  - **`PinPriority::HIGH`**: Recommended for performance-sensitive applications. Gives the MIDI thread priority to reduce latency.
  - **`PinPriority::EXCLUSIVE`**: Attempts to gain exclusive, real-time access. Provides the absolute lowest latency but may fail if the device is in use or doesn't support it.
  - **`PinPriority::LOW`**: Low priority, not recommended for real-time applications.
- **`maxMessageSize`**: Pre-allocates each async buffer to this size. Should be large enough to hold your biggest possible message (e.g., a large SysEx dump).
- **`asyncBuffers`**: The number of internal buffers used for asynchronous, non-blocking writes. More buffers can handle higher rates of outgoing messages without throwing a "buffers busy" exception.

**`void closePort()`**
-   Closes the currently open port, cancels all pending I/O, and releases handles.

**`bool isPortOpen() const noexcept`**
-   Returns `true` if a port is currently open and ready to send messages.

**`void sendMessage(const std::vector<BYTE>& message)`**
-   Sends a complete MIDI message non-blockingly.
-   **`message`**: A vector of bytes representing the message (e.g., `{0x90, 60, 100}`).

**`void sendMessage(const BYTE* message, size_t size)`**
-   Sends a complete MIDI message from a raw byte pointer non-blockingly.
-   **`message`**: Pointer to the first byte of the message.
-   **`size`**: The number of bytes in the message.


### `ksmidi::MidiIn`
A class for receiving MIDI messages from an input port. It features two distinct callback modes for balancing latency and safety.

**`MidiIn()`**
-   Default constructor.

**`~MidiIn()`**
-   Destructor. Automatically calls `closePort()` to stop listening threads and release resources.

**`void openPort(unsigned int portNumber, const Settings& settings = {})`**
-   Opens a connection to the specified MIDI input port and starts the listener thread.
-   **`portNumber`**: The ID of the input port to open.
-   **`settings`**: An optional `Settings` struct to precisely configure performance and behavior.

**`MidiIn::Settings` Struct**
```cpp
struct Settings {
    // Performance settings
    bool directCallback = false;                  // False for thread-safe queued mode (Default). True for lowest latency direct mode.
    PinPriority priority = PinPriority::NORMAL;   // Pin priority for latency control.

    // Buffer configuration
    DWORD bufferSize = 512;                       // Size of each internal I/O buffer. Larger for throughput.
    unsigned int bufferCount = 4;                 // Number of I/O buffers to use (minimum 2). More for smoother operation.

    // Message filtering
    bool ignoreSysex = false;                     // If true, ignore System Exclusive messages.
    bool ignoreTime = false;                      // If true, ignore MIDI Time Code, Start/Stop/Continue.
    bool ignoreSense = false;                     // If true, ignore Active Sensing and System Reset.
    size_t sysexChunkSize = 0;                    // 0 = deliver SysEx in one message. >0 = split into chunks of this size.

    // Advanced settings
    size_t queueSize = 1024;                      // (For Queued Mode) Size of message queue (must be power of 2).
    size_t maxSysexSize = 65536;                  // Max size for a non-chunked SysEx message or a parser's internal buffer.
};
```
*(See `MidiOut::Settings` for a detailed explanation of `PinPriority`.)*

**`void closePort()`**
-   Closes the open port, terminates background threads, and releases handles.

**`bool isPortOpen() const noexcept`**
-   Returns `true` if a port is currently open and listening for messages.

**`void setCallback(MessageCallback callback)`**
-   Sets the function to be called when a new MIDI message is received. **Where this callback executes depends on the `directCallback` setting.**
-   **`callback`**: A `std::function<void(const MidiMessage&)>`.

**`void cancelCallback()`**
-   Stops the callback mechanism. In Queued Mode, this also terminates the poller thread.

**`void setErrorCallback(ErrorCallback callback)`**
-   Sets a function for non-fatal runtime errors (e.g., device disconnected). This callback runs on the same thread as the message callback.
-   **`callback`**: A `std::function<void(const KsMidiError&)>`.

**`void ignoreTypes(bool midiSysex = false, bool midiTime = false, bool midiSense = false)`**
-   Dynamically filter system messages to reduce overhead. Defaults are `false` (process all messages).
-   **`midiSysex`**: Ignore System Exclusive messages (`0xF0` - `0xF7`).
-   **`midiTime`**: Ignore MIDI Time Code and System Common (`0xF1`, `0xF3`).
-   **`midiSense`**: Ignore Timing Clock, Start/Stop/Continue, Active Sensing, and System Reset (`0xF8` - `0xFF`).

**`bool try_pop_message(MidiMessage& message) noexcept`**
-   **For Queued Mode only.** If a message is available, it populates the `message` reference and returns `true`. Otherwise, it returns `false` immediately.

**`bool try_pop_error(KsMidiError& error) noexcept`**
-   **For Queued Mode only.** If a non-fatal error is available, it populates the `error` reference and returns `true`.

---

## Callback Modes: Direct vs. Queued
The `MidiIn::Settings::directCallback` flag is the most important performance tuning option.

#### Queued Mode (`directCallback = false`, Default)
This mode prioritizes **thread safety** over absolute lowest latency. It is the recommended default.
-   **Data Path:** Hardware -> OS -> Reader Thread -> **Message Queue** -> Poller Thread -> **Your Callback Function**
-   The I/O reader thread places incoming messages into a lock-free queue, and a separate, dedicated "poller" thread is responsible for reading from the queue and executing your callback.
-   **Pros:** Your callback runs on a predictable, separate thread, isolating it from the real-time I/O thread. It's much safer for complex processing. This mode is required for manual polling with `try_pop_message`.
-   **Cons:** Introduces a small amount of latency due to the queueing mechanism and the OS context switch between the reader and poller threads.

#### Direct Mode (`directCallback = true`)
This is the **lowest latency** mode, for applications where absolute low latency is important.
-   **Data Path:** Hardware -> OS -> Reader Thread -> **Your Callback Function**
-   When MIDI data arrives, your callback is executed **immediately** from within the library's high-priority I/O reader thread.
-   **Pros:** Minimal overhead, no extra thread context switches, lowest possible latency.
-   **Cons:** Your callback **must be extremely fast and thread-safe.** Avoid any blocking operations like file I/O, complex calculations, or locking a mutex that is also used by your main/UI thread, as this will block MIDI input.

### Threading Model & Performance

- **`MidiOut`**
  - **Asynchronous and Non-Blocking.** `sendMessage` returns immediately. It finds an available internal buffer and submits it to the OS for writing. If all buffers are busy with pending writes, it will throw a `KsMidiError` with code `ERROR_BUSY`. This design allows for extremely high message throughput. The class is thread-safe.

- **`MidiIn`**
  - **Asynchronous and Event-Driven.** The library uses overlapped I/O and does not use `sleep` or busy-waits.
  1.  **I/O Reader Thread**: A single, high-priority thread is created on `openPort()`. It waits on kernel events tied to the I/O buffers. When data arrives, this thread wakes up, processes the data, and then acts based on the callback mode.
  2.  **Callback Poller Thread**: This thread **only exists in Queued Mode**. It is created by `setCallback()`. It waits on a signal from the Reader Thread, then drains the message and error queues, invoking your callbacks for each item.

### SysEx Message Handling
-   If `settings.sysexChunkSize > 0`, large SysEx messages are split into multiple `MidiMessage` packets. Each packet will have `isSysExChunk = true`, except for the final one containing the `0xF7` byte, which will have `isSysExChunk = false`.
-   If `settings.sysexChunkSize = 0` (default), the parser buffers the entire message and delivers it as a single, complete `MidiMessage` object, up to `settings.maxSysexSize`.

### Error Handling
-   **Fatal Errors**: (e.g., invalid port, failure to create a kernel pin) throw a `KsMidiError` directly from the function you called (e.g., `openPort`). You must use a `try...catch` block to handle these.
-   **Non-Fatal Runtime Errors**: (e.g., a device is unplugged) are caught internally by the I/O Reader Thread.
    -   In **Direct Mode**, your `ErrorCallback` (if set) is invoked immediately.
    -   In **Queued Mode**, the error is pushed to a queue. You can receive it either via your `ErrorCallback` or by polling with `try_pop_error()`.
