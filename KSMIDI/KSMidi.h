/*
    KSMidi Public API – KSMidi.h
    ----------------------------
    Author: Mohamed Maatallah
    Date: June 27, 2025

    This is the public-facing C++ interface for the KSMidi library.
*/

#pragma once
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <atomic>
#include <thread>
#include <functional>

namespace ksmidi {

    /**
     * @class KsMidiError
     * @brief Exception class for all KSMidi library errors.
     * Inherits from std::runtime_error and includes the Windows HRESULT code.
     */
    class KsMidiError : public std::runtime_error {
    public:
        KsMidiError(const std::string& what = "Unknown KSMidi Error", HRESULT code = 0);

        /**
         * @brief Gets the HRESULT error code associated with the exception.
         * @return The Windows HRESULT code.
         */
        HRESULT code() const noexcept;
    private:
        HRESULT code_;
    };

    /**
     * @struct MidiMessage
     * @brief Represents a single and complete MIDI message or a chunk of a SysEx message.
     */
    struct MidiMessage {
        double timestamp = 0.0;          // High-resolution timestamp in seconds (QPC based)
        std::vector<BYTE> bytes;         // The raw bytes of the MIDI message
        std::string source;              // The friendly name of the port that sent the message
        bool isSysExChunk = false;       // True if this is an incomplete part of a larger SysEx message
    };

    /**
     * @struct DeviceInfo
     * @brief Contains detailed information about a MIDI device port.
     */
    struct DeviceInfo {
        unsigned int id = 0;             // The library-assigned port ID number
        std::string name;                // The user-friendly name of the device
        std::wstring path;               // The internal Windows device path
        DWORD pinId = 0;                 // The Kernel Streaming pin ID for this port
        bool isAvailable = true;         // True if the port is not currently in use by another application
    };

    /**
     * @class LockFreeSPSCQueue
     * @brief A high-performance, single-producer, single-consumer, lock-free circular queue.
     * @tparam T The type of elements in the queue.
     * @tparam Size The size of the queue buffer, which needs to be a power of two.
     */
    template<typename T, size_t Size>
    class LockFreeSPSCQueue {
        static_assert((Size > 0) && ((Size& (Size - 1)) == 0), "Queue size must be a power of two.");
    public:
        bool try_push(T&& value) noexcept {
            auto write_idx = writeIndex_.load(std::memory_order_relaxed);
            auto next_write_idx = (write_idx + 1) & (Size - 1);
            if (next_write_idx == readIndex_.load(std::memory_order_acquire)) return false; // full?
            buffer_[write_idx] = std::move(value);
            writeIndex_.store(next_write_idx, std::memory_order_release);
            return true;
        }

        bool try_pop(T& value) noexcept {
            auto read_idx = readIndex_.load(std::memory_order_relaxed);
            if (read_idx == writeIndex_.load(std::memory_order_acquire)) return false; // empty?
            value = std::move(buffer_[read_idx]);
            readIndex_.store((read_idx + 1) & (Size - 1), std::memory_order_release);
            return true;
        }

    private:
        T buffer_[Size];
        alignas(std::hardware_destructive_interference_size) std::atomic<size_t> writeIndex_{ 0 };
        alignas(std::hardware_destructive_interference_size) std::atomic<size_t> readIndex_{ 0 };
    };

    /**
     * @class Api
     * @brief A static-only class for querying available MIDI ports.
     */
    class Api {
    public:
        virtual ~Api() = default;
        static unsigned int getPortCountIn();
        static unsigned int getPortCountOut();
        static DeviceInfo getPortInfoIn(unsigned int portNumber);
        static DeviceInfo getPortInfoOut(unsigned int portNumber);
    };

    /**
     * @class MidiIn
     * @brief A class for receiving MIDI messages from an input port.
     */
    class MidiIn : public Api {
    public:
        using MessageCallback = std::function<void(const MidiMessage& message)>;
        using ErrorCallback = std::function<void(const KsMidiError& error)>;

        struct Settings {
            DWORD bufferSize = 512;        // Size of each individual I/O buffer
            unsigned int bufferCount = 4;   // Number of I/O buffers to use (min 2)
            size_t sysexChunkSize = 1024;   // Size for splitting large SysEx messages in callbacks (0 to disable)
            bool ignoreSysex = true;        // Initially ignore SysEx messages
            bool ignoreTime = true;         // Initially ignore Timing Clock and Start/Stop/Continue messages
            bool ignoreSense = true;        // Initially ignore Active Sensing and System Reset messages
        };

        MidiIn();
        ~MidiIn() noexcept;
        MidiIn(const MidiIn&) = delete;
        MidiIn& operator=(const MidiIn&) = delete;
        MidiIn(MidiIn&&) noexcept;
        MidiIn& operator=(MidiIn&&) noexcept;

        void openPort(unsigned int portNumber, const Settings& settings = {});
        void closePort();
        bool isPortOpen() const noexcept;

        bool try_pop_message(MidiMessage& message) noexcept;
        bool try_pop_error(KsMidiError& error) noexcept;

        void setCallback(MessageCallback callback);
        void cancelCallback();
        void setErrorCallback(ErrorCallback callback);

        void ignoreTypes(bool midiSysex = true, bool midiTime = true, bool midiSense = true);

    private:
        class MidiInImpl;
        std::unique_ptr<MidiInImpl> pimpl_;
    };

    /**
     * @class MidiOut
     * @brief A class for sending MIDI messages to an output port.
     */
    class MidiOut : public Api {
    public:
        MidiOut();
        ~MidiOut() noexcept;
        MidiOut(const MidiOut&) = delete;
        MidiOut& operator=(const MidiOut&) = delete;
        MidiOut(MidiOut&&) noexcept;
        MidiOut& operator=(MidiOut&&) noexcept;

        void openPort(unsigned int portNumber);
        void closePort();
        bool isPortOpen() const noexcept;

        void sendMessage(const std::vector<BYTE>& message);
        void sendMessage(const BYTE* message, size_t size);

    private:
        class MidiOutImpl;
        std::unique_ptr<MidiOutImpl> pimpl_;
    };

}
