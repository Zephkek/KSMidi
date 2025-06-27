# KSMidi API Documentation

This document provides a detailed overview of the KSMidi library's features, classes, and methods.

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
    *   [Threading Model](#threading-model)
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
A class for sending MIDI messages to an output port.

**`MidiOut()`**
-   Default constructor.

**`~MidiOut()`**
-   Destructor. Automatically calls `closePort()` to release system resources.

**`void openPort(unsigned int portNumber)`**
-   Opens a connection to the specified MIDI output port.
-   **`portNumber`**: The ID of the output port to open.
-   Throws a `KsMidiError` on failure (e.g., port not available, invalid ID).

**`void closePort()`**
-   Closes the currently open port and releases all associated handles.

**`bool isPortOpen() const noexcept`**
-   Returns `true` if a port is currently open and ready to send messages.

**`void sendMessage(const std::vector<BYTE>& message)`**
-   Sends a complete MIDI message.
-   **`message`**: A vector of bytes representing the message (e.g., `{0x90, 60, 100}`).

**`void sendMessage(const BYTE* message, size_t size)`**
-   Sends a complete MIDI message from a raw byte pointer.
-   **`message`**: Pointer to the first byte of the message.
-   **`size`**: The number of bytes in the message.

### `ksmidi::MidiIn`
A class for receiving MIDI messages from an input port.

**`MidiIn()`**
-   Default constructor.

**`~MidiIn()`**
-   Destructor. Automatically calls `closePort()` to stop listening threads and release resources.

**`void openPort(unsigned int portNumber, const Settings& settings = {})`**
-   Opens a connection to the specified MIDI input port and starts the listener thread.
-   **`portNumber`**: The ID of the input port to open.
-   **`settings`**: An optional `Settings` struct to configure I/O buffers.

**`MidiIn::Settings` Struct**
```cpp
struct Settings {
    DWORD bufferSize = 1024;      // Size of each internal I/O buffer.
    unsigned int bufferCount = 4; // Number of I/O buffers to use (minimum 2).
    size_t sysexChunkSize = 1024; // Size for splitting large SysEx messages (0 to disable).
};
```

**`void closePort()`**
-   Closes the open port, terminates background threads, and releases handles.

**`bool isPortOpen() const noexcept`**
-   Returns `true` if a port is currently open and listening for messages.

#### Message Handling
KSMidi provides two ways to receive messages: a real-time callback system or manual polling.

**Callback Model**
This is the recommended approach for real-time applications.

**`void setCallback(MessageCallback callback)`**
-   Sets a function to be called whenever a new MIDI message is received. The callback runs on a dedicated, high-priority poller thread.
-   **`callback`**: A `std::function<void(const MidiMessage&)>`.

**`void cancelCallback()`**
-   Stops the callback mechanism and terminates the poller thread.

**`void setErrorCallback(ErrorCallback callback)`**
-   Sets a function to be called for non-fatal runtime errors, such as a device being disconnected. The callback runs on the same thread as the message callback.
-   **`callback`**: A `std::function<void(const KsMidiError&)>`.

**Polling Model**
This approach gives you direct control over when to process messages.

**`bool try_pop_message(MidiMessage& message) noexcept`**
-   If a message is available in the queue, it populates the `message` reference and returns `true`. Otherwise, it returns `false` immediately.

**`bool try_pop_error(KsMidiError& error) noexcept`**
-   If a non-fatal error has occurred, it populates the `error` reference and returns `true`. Otherwise, it returns `false`.

#### Message Filtering

**`void ignoreTypes(bool midiSysex = true, bool midiTime = true, bool midiSense = true)`**
-   Allows you to dynamically filter out specific types of system messages to reduce processing overhead. By default, all are ignored.
-   **`midiSysex`**: If `true`, ignore all SysEx messages (`0xF0` - `0xF7`).
-   **`midiTime`**: If `true`, ignore MIDI Time Code and System Common messages (`0xF1`, `0xF3`).
-   **`midiSense`**: If `true`, ignore Timing Clock, Start/Stop/Continue, and Active Sensing (`0xF8` - `0xFF`).

---
## Threading Model

* **`MidiOut`**

  * Fully thread-safe: all calls to `sendMessage` (and internal state changes) are serialized by a `std::recursive_mutex` in `MidiOutImpl`.
* **`MidiIn`**
  Completely event-driven—no sleeps or polling inside the core library:

  1. **I/O Reader Thread**

     * On `openPort()` it issues N overlapped `IOCTL_KS_READ_STREAM` calls (one per buffer).
     * Blocks in `WaitForMultipleObjects` on the buffer events.
     * When a buffer’s event fires, it calls `GetOverlappedResult`, parses the raw bytes into `MidiMessage`(s) via `MidiParser`, pushes them into a lock-free SPSC queue, and then calls `SetEvent(callback_signal_event_)` to wake the poller if a callback is registered.
  2. **Callback Poller Thread**

     * Created when you call `setCallback(...)`.
     * Blocks in `WaitForSingleObject(callback_signal_event_)`.
     * When signaled, atomically drains **all** pending `MidiMessage`s and `KsMidiError`s from the two lock-free queues, invokes your `MessageCallback` and/or `ErrorCallback` for each, then re-blocks until the next event or until you call `cancelCallback()`.

---

### SysEx Message Handling

* Standard MIDI messages always arrive as single, complete `MidiMessage` objects.
* For SysEx:

  * If the message length exceeds `settings.sysexChunkSize > 0`, it’s split into multiple packets of up to that size, each with `isSysExChunk = true`.
  * The final packet (which includes the `0xF7` end-of-SysEx byte) is delivered with `isSysExChunk = false`.
  * If you set `settings.sysexChunkSize = 0`, chunking is disabled and the parser buffers the entire SysEx until it sees `0xF7`, then delivers one complete `MidiMessage`.

---

### Error Handling

* **Fatal Errors** (e.g. invalid port number, failure to open pin) throw a `KsMidiError` from the calling thread (you must `try…catch` around `openPort`, etc.).
* **Non-Fatal Runtime Errors** (e.g. stream read fails, device removal) are caught in the reader thread and pushed into the error queue. If you’ve registered an `ErrorCallback` with `setErrorCallback`, or if you poll with `try_pop_error()`, you’ll receive those errors without an exception being thrown, note that this doesn't work with virtual midi ports yet as the KS pin is never destroyed on those.
