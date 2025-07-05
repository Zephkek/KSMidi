/*
    KSMidi Public API – KSMidi.h
    ----------------------------
    Author: Mohamed Maatallah
    Date: June 28, 2025 (The Final Form)
    Modification: Added full MIDI 2.0 / UMP support with a dedicated UMP parser and API.

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
#include <optional>      // For C++17 std::optional
#include <string_view>   // For C++17 std::string_view
#include <new>           // For std::hardware_destructive_interference_size
#include <cstdint>       // For uint32_t, uint8_t
#include <array>         // For std::array

namespace ksmidi {

    /**
     * @class KsMidiError
     * @brief Exception class for all KSMidi library errors.
     * Inherits from std::runtime_error and includes the Windows HRESULT code.
     */
    class KsMidiError : public std::runtime_error {
    public:
        KsMidiError(std::string_view what = "Unknown KSMidi Error", HRESULT code = 0);
        HRESULT code() const noexcept;
    private:
        HRESULT code_;
    };

    /**
     * @struct MidiMessage
     * @brief Represents a single and complete MIDI 1.0 message or a chunk of a SysEx message.
     */
    struct MidiMessage {
        double timestamp = 0.0;          // Timestamp in seconds. Source and validity depends on MidiIn::Settings.
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
        bool supportsMidi2 = false;      // **NEW**: True if the underlying device reports MIDI 2.0 (UMP) support.
    };

    namespace ump {
        /**
        * @enum MessageType
        * @brief Defines the Message Type (MT) for a Universal MIDI Packet.
        */
        enum MessageType : uint8_t {
            UTILITY = 0x0,
            SYSTEM = 0x1,
            MIDI1_CHANNEL_VOICE = 0x2,
            SYSEX7_DATA = 0x3,
            MIDI2_CHANNEL_VOICE = 0x4,
            SYSEX8_DATA = 0x5,
            // Other reserved types omitted for brevity
        };

        /**
        * @struct UmpMessage
        * @brief Represents a single, complete Universal MIDI Packet (UMP).
        * The size can be 32, 64, 96, or 128 bits.
        */
        struct UmpMessage {
            double timestamp = 0.0;
            std::array<uint32_t, 4> words{};
            uint8_t size_in_words = 0; // Can be 1, 2, 3, or 4
            std::string source;
        };

        // --- UMP Helper Functions ---

        inline MessageType getMessageType(const UmpMessage& msg) {
            return static_cast<MessageType>((msg.words[0] >> 28) & 0x0F);
        }

        inline uint8_t getGroup(const UmpMessage& msg) {
            return (msg.words[0] >> 24) & 0x0F;
        }

        inline uint8_t getMidi1Channel(const UmpMessage& msg) {
            return (msg.words[0] >> 16) & 0x0F;
        }

        inline uint8_t getMidi1Status(const UmpMessage& msg) {
            return (msg.words[0] >> 20) & 0x0F;
        }

        inline uint8_t getNoteNumber(const UmpMessage& msg) {
            return (msg.words[0] >> 8) & 0x7F;
        }

        inline uint16_t getMidi2Velocity(const UmpMessage& msg) {
            return (msg.words[1] >> 16) & 0xFFFF;
        }

        /**
        * @brief Creates a 64-bit MIDI 2.0 Note On UMP.
        * @param group The UMP group (0-15).
        * @param channel The MIDI channel (0-15).
        * @param noteNumber The note number (0-127).
        * @param velocity The 16-bit velocity (0-65535).
        * @param attributeType The note attribute type (e.g., pitch-7.9).
        * @param attributeData The note attribute data.
        * @return A complete UmpMessage.
        */
        inline UmpMessage makeNoteOn(uint8_t group, uint8_t channel, uint8_t noteNumber, uint16_t velocity, uint8_t attributeType = 0, uint16_t attributeData = 0) {
            UmpMessage msg;
            msg.size_in_words = 2;
            msg.words[0] = (uint32_t(MessageType::MIDI2_CHANNEL_VOICE) << 28) | (uint32_t(group & 0xF) << 24) | (0x9 << 20) | (uint32_t(channel & 0xF) << 16) | (uint32_t(noteNumber) << 8) | attributeType;
            msg.words[1] = (uint32_t(velocity) << 16) | attributeData;
            return msg;
        }

        /**
        * @brief Creates a 64-bit MIDI 2.0 Note Off UMP.
        * @param group The UMP group (0-15).
        * @param channel The MIDI channel (0-15).
        * @param noteNumber The note number (0-127).
        * @param attributeType The note attribute type.
        * @param attributeData The note attribute data.
        * @return A complete UmpMessage.
        */
        inline UmpMessage makeNoteOff(uint8_t group, uint8_t channel, uint8_t noteNumber, uint8_t attributeType = 0, uint16_t attributeData = 0) {
            UmpMessage msg;
            msg.size_in_words = 2;
            msg.words[0] = (uint32_t(MessageType::MIDI2_CHANNEL_VOICE) << 28) | (uint32_t(group & 0xF) << 24) | (0x8 << 20) | (uint32_t(channel & 0xF) << 16) | (uint32_t(noteNumber) << 8) | attributeType;
            msg.words[1] = attributeData; // Velocity is zero
            return msg;
        }

    } // namespace ump


    /**
     * @class LockFreeSPSCQueue
     * @brief A high-performance, single-producer, single-consumer, lock-free circular queue.
     * @tparam T The type of elements in the queue.
     */
    template<typename T>
    class LockFreeSPSCQueue {
    public:
        explicit LockFreeSPSCQueue(size_t size) : size_(size), buffer_(new T[size]) {
            if (!size || (size & (size - 1)) != 0) {
                throw std::invalid_argument("LockFreeSPSCQueue size must be a power of two.");
            }
        }

        bool try_push(T&& value) noexcept {
            const auto write_idx = writeIndex_.load(std::memory_order_relaxed);
            const auto next_write_idx = (write_idx + 1) & (size_ - 1);
            if (next_write_idx == readIndex_.load(std::memory_order_acquire)) return false; // full?
            buffer_[write_idx] = std::move(value);
            writeIndex_.store(next_write_idx, std::memory_order_release);
            return true;
        }

        bool try_pop(T& value) noexcept {
            const auto read_idx = readIndex_.load(std::memory_order_relaxed);
            if (read_idx == writeIndex_.load(std::memory_order_acquire)) return false; // empty?
            value = std::move(buffer_[read_idx]);
            readIndex_.store((read_idx + 1) & (size_ - 1), std::memory_order_release);
            return true;
        }

        std::optional<T> pop() noexcept {
            const auto read_idx = readIndex_.load(std::memory_order_relaxed);
            if (read_idx == writeIndex_.load(std::memory_order_acquire)) return std::nullopt; // empty?

            std::optional<T> value = std::move(buffer_[read_idx]);
            readIndex_.store((read_idx + 1) & (size_ - 1), std::memory_order_release);
            return value;
        }

    private:
        const size_t size_;
        std::unique_ptr<T[]> buffer_;

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
        using UmpCallback = std::function<void(const ump::UmpMessage& message)>;
        using ErrorCallback = std::function<void(const KsMidiError& error)>;
        using DirectMessageCallback = void(*)(const BYTE* data, size_t size, double timestamp, void* userData);
        class MidiInImplBase;

        enum class TimestampMode {
            None,   ///< No timestamping. Message timestamp is always 0.0. Maximum performance.
            QPC,    ///< Timestamped via QueryPerformanceCounter when the event is processed. High precision, low overhead. (Default)
            Driver  ///< Timestamped by the kernel driver itself (KSSTREAM_HEADER::PresentationTime). Potentially the most accurate.
        };

        struct Settings {
            DWORD bufferSize = 512;
            unsigned int bufferCount = 4;
            size_t sysexChunkSize = 1024;
            bool ignoreSysex = true;
            bool ignoreTime = true;
            bool ignoreSense = true;

            TimestampMode timestampMode = TimestampMode::QPC;
            size_t messageQueueSize = 256;
            size_t umpMessageQueueSize = 256;
            size_t errorQueueSize = 16;
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
        bool isUmpStream() const noexcept;

        // --- MIDI 1.0 Byte Stream API ---
        bool try_pop_message(MidiMessage& message) noexcept;
        std::optional<MidiMessage> pop_message() noexcept;
        void setCallback(MessageCallback callback);
        void cancelCallback();

        // --- MIDI 2.0 Universal MIDI Packet API ---
        bool try_pop_ump_message(ump::UmpMessage& message) noexcept;
        std::optional<ump::UmpMessage> pop_ump_message() noexcept;
        void setUmpCallback(UmpCallback callback);
        void cancelUmpCallback();

        // --- Common API ---
        bool try_pop_error(KsMidiError& error) noexcept;
        std::optional<KsMidiError> pop_error() noexcept;
        void setErrorCallback(ErrorCallback callback);
        void ignoreTypes(bool midiSysex = true, bool midiTime = true, bool midiSense = true);

        // --- High-Performance (Direct) Callback API ---
        void setDirectCallback(DirectMessageCallback callback, void* userData = nullptr);
        void cancelDirectCallback();

    private:
        class MidiInImplBase;
        std::unique_ptr<MidiInImplBase> pimpl_;
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
        bool isUmpStream() const noexcept;

        // MIDI 1.0
        void sendMessage(const std::vector<BYTE>& message);
        void sendMessage(const BYTE* message, size_t size);

        // MIDI 2.0
        void sendMessage(const ump::UmpMessage& message);

    private:
        class MidiOutImpl;
        std::unique_ptr<MidiOutImpl> pimpl_;
    };

}
