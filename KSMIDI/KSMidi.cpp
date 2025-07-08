/*
    KSMidi Core Implementation – KSMidi.cpp
    ---------------------------------------
    Author: Mohamed Maatallah
    Date: June 28, 2025
    Version: 1.0.0

    This is the full internal implementation of the KSMidi library,
    responsible for interfacing directly with Windows Kernel Streaming (KS)
    to achieve low latency for MIDI input/output.

    MIT License
    
    Copyright (c) 2025 Mohamed Maatallah
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/

#include "KSMidi.h"

#include <avrt.h>
#include <initguid.h>
#include <ks.h>
#include <ksmedia.h>
#include <setupapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <utility>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ksuser.lib")
#pragma comment(lib, "avrt.lib")

// Aligns a value up to the nearest alignment boundary
#define KS_ALIGN_UP(v, a) (((v) + (a) - 1) & ~((a) - 1))

namespace ksmidi {
    namespace internal {

        struct HandleDeleter {
            void operator()(HANDLE h) const {
                if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
            }
        };
        using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

        struct DevInfoDeleter {
            void operator()(HDEVINFO h) const {
                if (h) SetupDiDestroyDeviceInfoList(h);
            }
        };
        using UniqueDevInfo =
            std::unique_ptr<std::remove_pointer_t<HDEVINFO>, DevInfoDeleter>;

        static std::string FormatWinError(HRESULT err) {
            char* msg = nullptr;
            DWORD len = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPSTR>(&msg), 0, nullptr);

            std::ostringstream os;
            os << " (0x" << std::hex << err << std::dec << ")";
            if (len > 0 && msg) {
                os << ": " << msg;
                LocalFree(msg);
            }
            return os.str();
        }

        // --- MIDI 1.0 Byte Stream Parser ---
        namespace {
            // Lookup table for MIDI message lengths (in data bytes, excluding status byte)
            constexpr std::array<uint8_t, 256> kBytesNeeded = [] {
                std::array<uint8_t, 256> t{};
                for (int s = 0; s < 256; ++s) {
                    uint8_t b = 0;
                    const uint8_t nibble = s & 0xF0;
                    if (nibble == 0xC0 || nibble == 0xD0 || s == 0xF1 || s == 0xF3)
                        b = 1;
                    else if ((nibble >= 0x80 && nibble <= 0xE0) || s == 0xF2)
                        b = 2;
                    t[s] = b;
                }
                return t;
                }();
        }  // namespace

        class MidiParser {
        public:
            struct Config {
                bool ignoreSysex{ true };
                bool ignoreTime{ true };
                bool ignoreSense{ true };
                size_t sysexChunkSize{ 1024 };
            };
            Config config;

            MidiParser() {
                message_buffer_.reserve(4);
                if (config.sysexChunkSize > 0) {
                    sysex_buffer_.reserve(config.sysexChunkSize);
                }
            }

            void process(const BYTE* data, DWORD size,
                LockFreeSPSCQueue<MidiMessage>& queue,
                const std::string& sourceName, double timestamp,
                HANDLE eventToSignal) {
                bool messagePushed = false;
                for (DWORD i = 0; i < size; ++i) {
                    if (parseByte(data[i], queue, sourceName, timestamp)) {
                        messagePushed = true;
                    }
                }
                if (messagePushed && eventToSignal) {
                    SetEvent(eventToSignal);
                }
            }

            void flush(LockFreeSPSCQueue<MidiMessage>& queue,
                const std::string& sourceName,
                double timestamp,
                HANDLE eventToSignal)
            {
                if (config.ignoreSysex || sysex_buffer_.empty())
                    return;

                MidiMessage msg;
                msg.timestamp = timestamp;
                msg.bytes = std::move(sysex_buffer_);
                msg.source = sourceName;
                msg.isSysExChunk = true;
                if (queue.try_push(std::move(msg))) {
                    if (eventToSignal) SetEvent(eventToSignal);
                    sysex_buffer_.clear();
                    sysex_buffer_.reserve(config.sysexChunkSize);
                }
            }

        private:
            bool parseByte(BYTE byte, LockFreeSPSCQueue<MidiMessage>& queue,
                const std::string& sourceName, double timestamp)
            {
                if (state_ == State::SysEx) {
                    if (byte == 0xF7) {
                        bool pushed = false;
                        if (!config.ignoreSysex) {
                            sysex_buffer_.push_back(byte);
                            MidiMessage msg;
                            msg.timestamp = timestamp;
                            msg.bytes = std::move(sysex_buffer_);
                            msg.source = sourceName;
                            if (queue.try_push(std::move(msg))) {
                                pushed = true;
                            }
                            sysex_buffer_.clear();
                            sysex_buffer_.reserve(config.sysexChunkSize);
                        }
                        state_ = State::Idle;
                        runningStatus_ = 0;
                        return pushed;
                    }
                    else {
                        if (!config.ignoreSysex) {
                            sysex_buffer_.push_back(byte);
                            size_t chunkSize = config.sysexChunkSize;
                            if (chunkSize > 0 && sysex_buffer_.size() >= chunkSize) {
                                MidiMessage chunkMsg;
                                chunkMsg.timestamp = timestamp;
                                chunkMsg.bytes = std::move(sysex_buffer_);
                                chunkMsg.source = sourceName;
                                chunkMsg.isSysExChunk = true;
                                bool pushed = queue.try_push(std::move(chunkMsg));
                                sysex_buffer_.clear();
                                sysex_buffer_.reserve(chunkSize);
                                return pushed;
                            }
                        }
                    }
                    return false;
                }

                if (byte >= 0xF8) {
                    bool shouldPush = false;
                    if (byte == 0xFF) {
                        shouldPush = !config.ignoreSense;
                    }
                    else if (byte >= 0xFA && byte <= 0xFC) {
                        shouldPush = !config.ignoreTime;
                    }
                    else if (byte == 0xFE) {
                        shouldPush = !config.ignoreSense;
                    }
                    else if (byte == 0xF8) {
                        shouldPush = !config.ignoreTime;
                    }

                    if (shouldPush) {
                        return queue.try_push({ timestamp, {byte}, sourceName, false });
                    }
                    return false;
                }

                if (byte >= 0x80) {
                    if (byte == 0xF0) {
                        state_ = State::SysEx;
                        sysex_buffer_.clear();
                        runningStatus_ = 0;
                        if (!config.ignoreSysex) {
                            sysex_buffer_.reserve(config.sysexChunkSize);
                            sysex_buffer_.push_back(byte);
                        }
                        return false;
                    }

                    message_buffer_.clear();
                    message_buffer_.push_back(byte);
                    bytesNeeded_ = kBytesNeeded[byte];
                    state_ = (bytesNeeded_ > 0) ? State::ExpectData : State::Idle;

                    if ((message_buffer_[0] & 0xF0) != 0xF0) {
                        runningStatus_ = message_buffer_[0];
                    }
                    else {
                        runningStatus_ = 0;
                    }

                    return (bytesNeeded_ == 0) ? handleCompleteMessage(queue, sourceName, timestamp) : false;
                }
                else {
                    if (state_ == State::Idle) {
                        if (runningStatus_ == 0) return false;
                        message_buffer_.clear();
                        message_buffer_.push_back(runningStatus_);
                        bytesNeeded_ = kBytesNeeded[runningStatus_];
                        state_ = State::ExpectData;
                    }
                    message_buffer_.push_back(byte);
                    if (message_buffer_.size() == static_cast<size_t>(bytesNeeded_ + 1)) {
                        state_ = State::Idle;
                        return handleCompleteMessage(queue, sourceName, timestamp);
                    }
                }
                return false;
            }

            bool handleCompleteMessage(LockFreeSPSCQueue<MidiMessage>& queue,
                const std::string& sourceName, double timestamp) {
                BYTE status = message_buffer_[0];
                bool shouldPush = false;
                if (status < 0xF0) {
                    shouldPush = true;
                }
                else {  // System common
                    if (!config.ignoreTime && (status >= 0xF1 && status <= 0xF3)) {
                        shouldPush = true;
                    }
                    else if (status == 0xF6) {  // Tune Request, not filtered by "sense"
                        shouldPush = true;
                    }
                }
                if (shouldPush) {
                    MidiMessage msg;
                    msg.timestamp = timestamp;
                    msg.bytes = std::move(message_buffer_);
                    msg.source = sourceName;
                    message_buffer_.clear();
                    message_buffer_.reserve(4);  // Keep capacity for next message
                    return queue.try_push(std::move(msg));
                }
                return false;
            }

            enum class State { Idle, ExpectData, SysEx };
            State state_{ State::Idle };
            std::vector<BYTE> message_buffer_;
            std::vector<BYTE> sysex_buffer_;
            BYTE runningStatus_ = 0;
            int bytesNeeded_ = 0;
        };

        // --- MIDI 2.0 UMP Parser ---
        class UmpParser {
        public:
            void process(const BYTE* data, DWORD size,
                LockFreeSPSCQueue<ump::UmpMessage>& queue,
                const std::string& sourceName, double timestamp,
                HANDLE eventToSignal) {
                bool messagePushed = false;
                for (DWORD i = 0; i < size; ++i) {
                    if (parseByte(data[i], queue, sourceName, timestamp)) {
                        messagePushed = true;
                    }
                }
                if (messagePushed && eventToSignal) {
                    SetEvent(eventToSignal);
                }
            }

        private:
            static uint8_t getUmpPacketSizeInWords(uint8_t messageType) {
                // Official MIDI 2.0 UMP packet sizes based on Message Type (MT)
                static constexpr uint8_t sizes[16] = { 1, 1, 1, 1, 2, 4, 1, 1,
                                                     2, 2, 2, 3, 3, 4, 4, 4 };
                return sizes[messageType & 0x0F];
            }

            bool parseByte(BYTE byte, LockFreeSPSCQueue<ump::UmpMessage>& queue,
                const std::string& sourceName, double timestamp) {
                if (bytesReceived_ >= packetBuffer_.size()) {
                    bytesReceived_ = 0;
                    state_ = State::AwaitingPacket;
                }
                packetBuffer_[bytesReceived_++] = byte;

                if (state_ == State::AwaitingPacket) {
                    if (bytesReceived_ == 4) {  // We have the first 32-bit word
                        uint8_t mt = (packetBuffer_[0] >> 4) & 0x0F;
                        wordsExpected_ = getUmpPacketSizeInWords(mt);
                        if (wordsExpected_ == 1)
                            return pushCompletePacket(queue, sourceName, timestamp);
                        else if (wordsExpected_ > 1 && wordsExpected_ <= 4)
                            state_ = State::AwaitingData;
                        else {
                            bytesReceived_ = 0;
                            wordsExpected_ = 0;
                        }
                    }
                }
                else {  // AwaitingData
                    if (bytesReceived_ == (wordsExpected_ * 4)) {
                        return pushCompletePacket(queue, sourceName, timestamp);
                    }
                }
                return false;
            }

            bool pushCompletePacket(LockFreeSPSCQueue<ump::UmpMessage>& queue,
                const std::string& sourceName, double timestamp) {
                ump::UmpMessage msg;
                msg.timestamp = timestamp;
                msg.source = sourceName;
                msg.size_in_words = wordsExpected_;
                for (uint8_t i = 0; i < wordsExpected_; ++i) {
                    msg.words[i] = (static_cast<uint32_t>(packetBuffer_[i * 4]) << 24) |
                        (static_cast<uint32_t>(packetBuffer_[i * 4 + 1]) << 16) |
                        (static_cast<uint32_t>(packetBuffer_[i * 4 + 2]) << 8) |
                        static_cast<uint32_t>(packetBuffer_[i * 4 + 3]);
                }
                state_ = State::AwaitingPacket;
                bytesReceived_ = 0;
                wordsExpected_ = 0;
                return queue.try_push(std::move(msg));
            }

            enum class State { AwaitingPacket, AwaitingData };
            State state_ = State::AwaitingPacket;
            std::array<BYTE, 16> packetBuffer_{};
            uint8_t bytesReceived_ = 0;
            uint8_t wordsExpected_ = 0;
        };

        // --- Device Enumeration ---
        class DeviceEnumerator {
        public:
            static std::vector<DeviceInfo> enumerate(const GUID& category,
                KSPIN_DATAFLOW flow) {
                UniqueDevInfo devInfo(SetupDiGetClassDevs(
                    &category, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
                if (!devInfo) {
                    throw KsMidiError("SetupDiGetClassDevs failed",
                        static_cast<HRESULT>(GetLastError()));
                }

                std::vector<DeviceInfo> devices;
                SP_DEVICE_INTERFACE_DATA ifd{ sizeof(ifd) };

                for (DWORD i = 0; SetupDiEnumDeviceInterfaces(devInfo.get(), nullptr,
                    &category, i, &ifd);
                    ++i) {
                    DWORD neededBytes = 0;
                    SetupDiGetDeviceInterfaceDetailW(devInfo.get(), &ifd, nullptr, 0,
                        &neededBytes, nullptr);
                    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;

                    std::vector<BYTE> detailBuffer(neededBytes);
                    auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(
                        detailBuffer.data());
                    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

                    if (!SetupDiGetDeviceInterfaceDetailW(devInfo.get(), &ifd, detail,
                        neededBytes, nullptr, nullptr))
                        continue;

                    UniqueHandle filter(CreateFileW(detail->DevicePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr));
                    if (!filter || filter.get() == INVALID_HANDLE_VALUE) continue;

                    KSPROPERTY pinProp{ KSPROPSETID_Pin, KSPROPERTY_PIN_CTYPES,
                                       KSPROPERTY_TYPE_GET };
                    DWORD pinCount = 0, bytesReturned = 0;
                    if (!DeviceIoControl(filter.get(), IOCTL_KS_PROPERTY, &pinProp,
                        sizeof(pinProp), &pinCount, sizeof(pinCount),
                        &bytesReturned, nullptr))
                        continue;

                    for (DWORD pinId = 0; pinId < pinCount; ++pinId) {
                        auto support = getPinMidiSupport(filter.get(), pinId, flow);
                        if (support.first) {
                            devices.push_back(
                                { static_cast<unsigned int>(devices.size()),
                                 getFriendlyName(devInfo.get(), &ifd), detail->DevicePath, pinId,
                                 getAvailableInstances(filter.get(), pinId) > 0, support.second });
                        }
                    }
                }
                return devices;
            }

        private:
            static std::pair<bool, bool> getPinMidiSupport(HANDLE filter, DWORD pinId,
                KSPIN_DATAFLOW desiredFlow) {
                KSP_PIN pinFlowProp{
                    {KSPROPSETID_Pin, KSPROPERTY_PIN_DATAFLOW, KSPROPERTY_TYPE_GET},
                    pinId,
                    0 };
                KSPIN_DATAFLOW flow;
                DWORD bytesReturned = 0;
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinFlowProp,
                    sizeof(pinFlowProp), &flow, sizeof(flow),
                    &bytesReturned, nullptr) ||
                    flow != desiredFlow)
                    return { false, false };

                KSP_PIN pinRangeProp{
                    {KSPROPSETID_Pin, KSPROPERTY_PIN_DATARANGES, KSPROPERTY_TYPE_GET},
                    pinId,
                    0 };
                ULONG size = 0;
                DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp,
                    sizeof(pinRangeProp), nullptr, 0, &size, nullptr);
                if (size == 0) return { false, false };

                std::vector<BYTE> buffer(size);
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp,
                    sizeof(pinRangeProp), buffer.data(), size,
                    &bytesReturned, nullptr))
                    return { false, false };

                bool supportsMidi1 = false, supportsMidi2 = false;
                auto* multipleItem = reinterpret_cast<PKSMULTIPLE_ITEM>(buffer.data());
                auto* dataRange = reinterpret_cast<PKSDATARANGE>(multipleItem + 1);

                for (ULONG i = 0; i < multipleItem->Count; ++i) {
                    if (IsEqualGUID(dataRange->MajorFormat, KSDATAFORMAT_TYPE_MUSIC)) {
                        if (IsEqualGUID(dataRange->SubFormat, KSDATAFORMAT_SUBTYPE_MIDI))
                            supportsMidi1 = true;
                        else if (IsEqualGUID(dataRange->SubFormat,
                            KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET))
                            supportsMidi2 = true;
                    }
                    dataRange =
                        reinterpret_cast<PKSDATARANGE>(reinterpret_cast<PBYTE>(dataRange) +
                            KS_ALIGN_UP(dataRange->FormatSize, 8));
                }
                return { supportsMidi1 || supportsMidi2, supportsMidi2 };
            }

            static long getAvailableInstances(HANDLE filter, DWORD pinId) {
                KSP_PIN pinInstancesProp{
                    {KSPROPSETID_Pin, KSPROPERTY_PIN_CINSTANCES, KSPROPERTY_TYPE_GET},
                    pinId,
                    0 };
                KSPIN_CINSTANCES instances{};
                DWORD bytesReturned = 0;
                if (DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinInstancesProp,
                    sizeof(pinInstancesProp), &instances, sizeof(instances),
                    &bytesReturned, nullptr)) {
                    return instances.PossibleCount - instances.CurrentCount;
                }
                return 0;
            }

            static std::string getFriendlyName(HDEVINFO devInfo,
                SP_DEVICE_INTERFACE_DATA* ifd) {
                char name[256] = "Unknown Device";
                HKEY regKey = SetupDiOpenDeviceInterfaceRegKey(devInfo, ifd, 0, KEY_READ);
                if (regKey != INVALID_HANDLE_VALUE) {
                    WCHAR wName[256]{};
                    DWORD size = sizeof(wName);
                    if (RegQueryValueExW(regKey, L"FriendlyName", nullptr, nullptr,
                        reinterpret_cast<LPBYTE>(wName),
                        &size) == ERROR_SUCCESS) {
                        WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, sizeof(name), nullptr,
                            nullptr);
                    }
                    RegCloseKey(regKey);
                }
                return name;
            }
        };
    }  // namespace internal

    KsMidiError::KsMidiError(std::string_view what, HRESULT code)
        : std::runtime_error(std::string(what) + internal::FormatWinError(code)),
        code_(code) {
    }
    HRESULT KsMidiError::code() const noexcept { return code_; }
    unsigned int Api::getPortCountIn() {
        return static_cast<unsigned int>(internal::DeviceEnumerator::enumerate(
            KSCATEGORY_CAPTURE, KSPIN_DATAFLOW_OUT)
            .size());
    }
    unsigned int Api::getPortCountOut() {
        return static_cast<unsigned int>(internal::DeviceEnumerator::enumerate(
            KSCATEGORY_RENDER, KSPIN_DATAFLOW_IN)
            .size());
    }
    DeviceInfo Api::getPortInfoIn(unsigned int portNumber) {
        auto devices = internal::DeviceEnumerator::enumerate(KSCATEGORY_CAPTURE,
            KSPIN_DATAFLOW_OUT);
        if (portNumber >= devices.size())
            throw KsMidiError("Invalid input port number specified.", E_INVALIDARG);
        return devices[portNumber];
    }
    DeviceInfo Api::getPortInfoOut(unsigned int portNumber) {
        auto devices = internal::DeviceEnumerator::enumerate(KSCATEGORY_RENDER,
            KSPIN_DATAFLOW_IN);
        if (portNumber >= devices.size())
            throw KsMidiError("Invalid output port number specified.", E_INVALIDARG);
        return devices[portNumber];
    }

    // --- MidiOut Implementation ---
    class MidiOut::MidiOutImpl {
    public:
        MidiOutImpl() {
            writeBuffer_.reserve(2048);
        }
        ~MidiOutImpl() noexcept { closePort(); }

        void openPort(unsigned int portNumber) {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
            info_ = Api::getPortInfoOut(portNumber);
            if (!info_.isAvailable)
                throw KsMidiError("Output port '" + info_.name + "' is not available.",
                    E_ACCESSDENIED);

            filter_.reset(CreateFileW(info_.path.c_str(), GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, 0, nullptr));
            if (!filter_ || filter_.get() == INVALID_HANDLE_VALUE)
                throw KsMidiError("Failed to open device filter",
                    static_cast<HRESULT>(GetLastError()));

            const size_t connectSize = sizeof(KSPIN_CONNECT) + sizeof(KSDATAFORMAT);
            std::vector<BYTE> connectBuffer(connectSize);
            auto* connect = reinterpret_cast<PKSPIN_CONNECT>(connectBuffer.data());
            auto* dataFormat = reinterpret_cast<PKSDATAFORMAT>(connect + 1);
            connect->Interface = { KSINTERFACESETID_Standard,
                                  KSINTERFACE_STANDARD_STREAMING, 0 };
            connect->Medium = { KSMEDIUMSETID_Standard, 0, 0 };
            connect->PinId = info_.pinId;
            connect->Priority = { KSPRIORITY_NORMAL, 1 };
            *dataFormat = { sizeof(KSDATAFORMAT),
                           0,
                           0,
                           0,
                           KSDATAFORMAT_TYPE_MUSIC,
                           info_.supportsMidi2
                               ? KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET
                               : KSDATAFORMAT_SUBTYPE_MIDI,
                           KSDATAFORMAT_SPECIFIER_NONE };

            HANDLE rawPinHandle = nullptr;
            HRESULT hr =
                KsCreatePin(filter_.get(), connect, GENERIC_WRITE, &rawPinHandle);
            if (FAILED(hr)) throw KsMidiError("Failed to create output pin.", hr);
            pin_.reset(rawPinHandle);

            setPinState(KSSTATE_ACQUIRE);
            setPinState(KSSTATE_RUN);
        }

        void closePort() {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
        }

        bool isPortOpen() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return pin_ != nullptr;
        }

        bool isUmpStream() const noexcept { return info_.supportsMidi2; }

        void sendMessageImpl(const BYTE* message, size_t size) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!pin_ || !message || size == 0) return;

            if (size > (std::numeric_limits<DWORD>::max() - sizeof(KSMUSICFORMAT)))
                throw KsMidiError("MIDI message is too large.", E_OUTOFMEMORY);

            const DWORD payloadSize = sizeof(KSMUSICFORMAT) + static_cast<DWORD>(size);

            if (writeBuffer_.size() < payloadSize) {
                writeBuffer_.resize(payloadSize);
            }

            auto* musicHeader = reinterpret_cast<PKSMUSICFORMAT>(writeBuffer_.data());
            musicHeader->TimeDeltaMs = 0;
            musicHeader->ByteCount = static_cast<DWORD>(size);

            if (size > 0) {
                std::memcpy(writeBuffer_.data() + sizeof(KSMUSICFORMAT), message, size);
            }

            KSSTREAM_HEADER streamHeader{};
            streamHeader.Size = sizeof(streamHeader);
            streamHeader.Data = writeBuffer_.data();
            streamHeader.FrameExtent = KS_ALIGN_UP(payloadSize, 8);
            streamHeader.DataUsed = streamHeader.FrameExtent;

            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_WRITE_STREAM, nullptr, 0,
                &streamHeader, sizeof(streamHeader), &bytesReturned,
                nullptr)) {
                throw KsMidiError("Failed to write to MIDI stream.",
                    static_cast<HRESULT>(GetLastError()));
            }
        }

    private:
        void closePortImpl() {
            if (!pin_) return;
            try {
                setPinState(KSSTATE_STOP);
            }
            catch (const KsMidiError&) {
            }
            pin_.reset();
            filter_.reset();
            info_ = {};
        }

        void setPinState(KSSTATE state) {
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE,
                            KSPROPERTY_TYPE_SET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop),
                &state, sizeof(state), &bytesReturned, nullptr)) {
                if (state != KSSTATE_STOP)
                    throw KsMidiError("Failed to set pin state",
                        static_cast<HRESULT>(GetLastError()));
            }
        }

        mutable std::mutex mutex_;
        DeviceInfo info_;
        internal::UniqueHandle filter_, pin_;
        std::vector<BYTE> writeBuffer_;
    };
    MidiOut::MidiOut() : pimpl_(std::make_unique<MidiOutImpl>()) {}
    MidiOut::~MidiOut() noexcept {
        try {
            pimpl_->closePort();
        }
        catch (...) {
        }
    }
    MidiOut::MidiOut(MidiOut&&) noexcept = default;
    MidiOut& MidiOut::operator=(MidiOut&&) noexcept = default;
    void MidiOut::openPort(unsigned int portNumber) {
        pimpl_->openPort(portNumber);
    }
    void MidiOut::closePort() { pimpl_->closePort(); }
    bool MidiOut::isPortOpen() const noexcept {
        return pimpl_ ? pimpl_->isPortOpen() : false;
    }
    bool MidiOut::isUmpStream() const noexcept {
        return pimpl_ ? pimpl_->isUmpStream() : false;
    }
    void MidiOut::sendMessage(const std::vector<BYTE>& message) {
        pimpl_->sendMessageImpl(message.data(), message.size());
    }
    void MidiOut::sendMessage(const BYTE* message, size_t size) {
        pimpl_->sendMessageImpl(message, size);
    }
    void MidiOut::sendMessage(const ump::UmpMessage& message) {
        pimpl_->sendMessageImpl(reinterpret_cast<const BYTE*>(message.words.data()),
            message.size_in_words * 4);
    }

    // --- MidiIn Implementation ---
    class MidiIn::MidiInImplBase {
    public:
        virtual ~MidiInImplBase() = default;
        virtual void openPort(unsigned int) = 0;
        virtual void closePort() = 0;
        virtual bool isPortOpen() const noexcept = 0;
        virtual bool isUmpStream() const noexcept = 0;
        virtual bool try_pop_message(MidiMessage&) noexcept = 0;
        virtual std::optional<MidiMessage> pop_message() noexcept = 0;
        virtual void setCallback(MessageCallback) = 0;
        virtual void cancelCallback() = 0;
        virtual bool try_pop_ump_message(ump::UmpMessage&) noexcept = 0;
        virtual std::optional<ump::UmpMessage> pop_ump_message() noexcept = 0;
        virtual void setUmpCallback(UmpCallback) = 0;
        virtual void cancelUmpCallback() = 0;
        virtual bool try_pop_error(KsMidiError&) noexcept = 0;
        virtual std::optional<KsMidiError> pop_error() noexcept = 0;
        virtual void setDirectCallback(DirectMessageCallback, void*) = 0;
        virtual void cancelDirectCallback() = 0;
        virtual void setErrorCallback(ErrorCallback) = 0;
    };

    template <MidiIn::TimestampMode TMode>
    class MidiIn::MidiInImpl final : public MidiIn::MidiInImplBase {
        struct ReadRequest {
            internal::UniqueHandle event;
            std::vector<BYTE> data;
            KSSTREAM_HEADER header{};
            OVERLAPPED overlapped{};
            ReadRequest(DWORD bufferSize) : data(bufferSize) {
                event.reset(CreateEvent(nullptr, TRUE, FALSE, nullptr));
                overlapped.hEvent = event.get();
                header.Size = sizeof(header);
                header.Data = data.data();
                header.FrameExtent = bufferSize;
            }
        };

    public:
        explicit MidiInImpl(const MidiIn::Settings& settings)
            : settings_(settings),
            messageQueue_(settings.messageQueueSize),
            umpMessageQueue_(settings.umpMessageQueueSize),
            errorQueue_(settings.errorQueueSize) {
            if (settings.bufferCount < 2 || settings.bufferCount > MAXIMUM_WAIT_OBJECTS)
                throw KsMidiError("Buffer count must be between 2 and 64.", E_INVALIDARG);
            if constexpr (TMode == MidiIn::TimestampMode::QPC) {
                LARGE_INTEGER freq;
                QueryPerformanceFrequency(&freq);
                perf_freq_reciprocal_ = 1.0 / static_cast<double>(freq.QuadPart);
            }
        }
        ~MidiInImpl() noexcept override { closePort(); }

        void openPort(unsigned int portNumber) override {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
            info_ = Api::getPortInfoIn(portNumber);
            isUmpStream_ = info_.supportsMidi2;
            if (!info_.isAvailable)
                throw KsMidiError("Input port '" + info_.name + "' is not available.",
                    E_ACCESSDENIED);

            callback_signal_event_.reset(CreateEvent(nullptr, FALSE, FALSE, nullptr));
            ump_callback_signal_event_.reset(
                CreateEvent(nullptr, FALSE, FALSE, nullptr));
            filter_.reset(CreateFileW(info_.path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                nullptr));
            if (!filter_ || filter_.get() == INVALID_HANDLE_VALUE)
                throw KsMidiError("Failed to open device filter",
                    static_cast<HRESULT>(GetLastError()));

            const size_t connectSize = sizeof(KSPIN_CONNECT) + sizeof(KSDATAFORMAT);
            std::vector<BYTE> connectBuffer(connectSize);
            auto* connect = reinterpret_cast<PKSPIN_CONNECT>(connectBuffer.data());
            auto* dataFormat = reinterpret_cast<PKSDATAFORMAT>(connect + 1);
            connect->Interface = { KSINTERFACESETID_Standard,
                                  KSINTERFACE_STANDARD_STREAMING, 0 };
            connect->Medium = { KSMEDIUMSETID_Standard, 0, 0 };
            connect->PinId = info_.pinId;
            connect->Priority = { KSPRIORITY_NORMAL, 1 };
            *dataFormat = { sizeof(KSDATAFORMAT),
                           0,
                           0,
                           0,
                           KSDATAFORMAT_TYPE_MUSIC,
                           isUmpStream_ ? KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET
                                        : KSDATAFORMAT_SUBTYPE_MIDI,
                           KSDATAFORMAT_SPECIFIER_NONE };

            HANDLE rawPinHandle = nullptr;
            HRESULT hr =
                KsCreatePin(filter_.get(), connect, GENERIC_READ, &rawPinHandle);
            if (FAILED(hr)) throw KsMidiError("Failed to create input pin.", hr);
            pin_.reset(rawPinHandle);

            setPinState(KSSTATE_ACQUIRE);
            setPinState(KSSTATE_RUN);

            parser_.config = { settings_.ignoreSysex, settings_.ignoreTime,
                              settings_.ignoreSense, settings_.sysexChunkSize };
            stop_flag_ = false;
            timestamp_baseline_ = 0.0;
            baseline_is_set_ = false;
            driver_time_accumulator_ = 0.0;
            driver_stream_baseline_ = 0.0;
            driver_stream_baseline_set_ = false;
            reader_thread_ = std::thread(&MidiInImpl::readerLoop, this);
        }
        void closePort() override {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
        }
        bool isPortOpen() const noexcept override {
            return !stop_flag_.load(std::memory_order_relaxed);
        }
        bool isUmpStream() const noexcept override { return isUmpStream_; }
        bool try_pop_message(MidiMessage& m) noexcept override {
            return messageQueue_.try_pop(m);
        }
        std::optional<MidiMessage> pop_message() noexcept override {
            return messageQueue_.pop();
        }
        void setCallback(MessageCallback cb) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelDirectCallbackImpl();
            cancelUmpCallbackImpl();
            cancelCallbackImpl();
            message_callback_ = std::move(cb);
            if (message_callback_) {
                stop_polling_ = false;
                poller_thread_ = std::thread(&MidiInImpl::pollingLoop, this);
            }
        }
        void cancelCallback() override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelCallbackImpl();
        }
        bool try_pop_ump_message(ump::UmpMessage& m) noexcept override {
            return umpMessageQueue_.try_pop(m);
        }
        std::optional<ump::UmpMessage> pop_ump_message() noexcept override {
            return umpMessageQueue_.pop();
        }
        void setUmpCallback(UmpCallback cb) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelDirectCallbackImpl();
            cancelCallbackImpl();
            cancelUmpCallbackImpl();
            ump_callback_ = std::move(cb);
            if (ump_callback_) {
                stop_ump_polling_ = false;
                ump_poller_thread_ = std::thread(&MidiInImpl::umpPollingLoop, this);
            }
        }
        void cancelUmpCallback() override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelUmpCallbackImpl();
        }
        bool try_pop_error(KsMidiError& e) noexcept override {
            return errorQueue_.try_pop(e);
        }
        std::optional<KsMidiError> pop_error() noexcept override {
            return errorQueue_.pop();
        }
        void setDirectCallback(DirectMessageCallback cb, void* ud) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelCallbackImpl();
            cancelUmpCallbackImpl();
            direct_callback_user_data_.store(ud, std::memory_order_release);
            direct_callback_.store(cb, std::memory_order_release);
        }
        void cancelDirectCallback() override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelDirectCallbackImpl();
        }
        void setErrorCallback(ErrorCallback cb) override {
            std::lock_guard<std::mutex> lock(mutex_);
            error_callback_ = std::move(cb);
        }

    private:
        void closePortImpl() {
            if (stop_flag_.exchange(true, std::memory_order_acq_rel) ||
                !reader_thread_.joinable())
                return;

            cancelCallbackImpl();
            cancelUmpCallbackImpl();
            cancelDirectCallbackImpl();

            if (pin_) CancelIoEx(pin_.get(), nullptr);
            if (reader_thread_.joinable()) reader_thread_.join();

            if (pin_) {
                parser_.flush(messageQueue_, info_.name, 0.0,
                    callback_signal_event_.get());
                try {
                    setPinState(KSSTATE_STOP);
                }
                catch (...) {
                }
            }

            pin_.reset();
            filter_.reset();
            info_ = {};
            isUmpStream_ = false;
        }
        void cancelCallbackImpl() {
            if (!poller_thread_.joinable()) return;
            stop_polling_ = true;
            if (callback_signal_event_) SetEvent(callback_signal_event_.get());
            poller_thread_.join();
            message_callback_ = nullptr;
        }
        void cancelUmpCallbackImpl() {
            if (!ump_poller_thread_.joinable()) return;
            stop_ump_polling_ = true;
            if (ump_callback_signal_event_) SetEvent(ump_callback_signal_event_.get());
            ump_poller_thread_.join();
            ump_callback_ = nullptr;
        }
        void cancelDirectCallbackImpl() {
            direct_callback_.store(nullptr, std::memory_order_release);
            direct_callback_user_data_.store(nullptr, std::memory_order_release);
        }
        void pollingLoop() {
            while (!stop_polling_) {
                WaitForSingleObject(callback_signal_event_.get(), INFINITE);
                if (stop_polling_) break;
                while (auto m = messageQueue_.pop())
                    if (message_callback_) message_callback_(*m);
                while (auto e = errorQueue_.pop())
                    if (error_callback_) error_callback_(*e);
            }
            while (auto m = messageQueue_.pop())
                if (message_callback_) message_callback_(*m);
        }
        void umpPollingLoop() {
            while (!stop_ump_polling_) {
                WaitForSingleObject(ump_callback_signal_event_.get(), INFINITE);
                if (stop_ump_polling_) break;
                while (auto m = umpMessageQueue_.pop())
                    if (ump_callback_) ump_callback_(*m);
                while (auto e = errorQueue_.pop())
                    if (error_callback_) error_callback_(*e);
            }
            while (auto m = umpMessageQueue_.pop())
                if (ump_callback_) ump_callback_(*m);
        }
        void readerLoop() {
            std::vector<std::unique_ptr<ReadRequest>> reqs;
            std::vector<HANDLE> evts;
            for (unsigned int i = 0; i < settings_.bufferCount; ++i) {
                reqs.push_back(std::make_unique<ReadRequest>(settings_.bufferSize));
                evts.push_back(reqs.back()->event.get());
            }
            for (auto& req : reqs)
                if (!queueRead(*req)) {
                    stop_flag_ = true;
                    break;
                }
            while (!stop_flag_) {
                DWORD r = WaitForMultipleObjects(static_cast<DWORD>(evts.size()),
                    evts.data(), FALSE, INFINITE);
                if (stop_flag_) break;
                if (r >= WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + evts.size()) {
                    DWORD br = 0;
                    if (GetOverlappedResult(
                        pin_.get(), &reqs[r - WAIT_OBJECT_0]->overlapped, &br, FALSE) &&
                        br > 0)
                        processData(reqs[r - WAIT_OBJECT_0]->header);
                    if (!stop_flag_) queueRead(*reqs[r - WAIT_OBJECT_0]);
                }
                else {
                    errorQueue_.try_push({ "MIDI listener wait failed.",
                                          static_cast<HRESULT>(GetLastError()) });
                    if (callback_signal_event_) SetEvent(callback_signal_event_.get());
                    break;
                }
            }
        }
        bool queueRead(ReadRequest& req) {
            ResetEvent(req.event.get());
            std::memset(req.data.data(), 0, req.data.size());
            req.header.DataUsed = 0;
            req.header.PresentationTime = { 0, 1, 1 };
            DWORD br = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_READ_STREAM, nullptr, 0,
                &req.header, sizeof(req.header), &br,
                &req.overlapped)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    errorQueue_.try_push(
                        { "Fatal stream read error.", static_cast<HRESULT>(GetLastError()) });
                    if (callback_signal_event_) SetEvent(callback_signal_event_.get());
                    return false;
                }
            }
            return true;
        }

        void processData(const KSSTREAM_HEADER& header) noexcept {
            double buffer_qpc_ts = 0.0;
            if constexpr (TMode == TimestampMode::QPC) {
                LARGE_INTEGER n;
                QueryPerformanceCounter(&n);
                buffer_qpc_ts = static_cast<double>(n.QuadPart) * perf_freq_reciprocal_;
                if (!baseline_is_set_.load(std::memory_order_relaxed)) {
                    timestamp_baseline_ = buffer_qpc_ts;
                    baseline_is_set_.store(true, std::memory_order_relaxed);
                }
            }
            else if constexpr (TMode == TimestampMode::Driver) {
                if (header.PresentationTime.Numerator &&
                    header.PresentationTime.Denominator) {
                    const double abs_sec =
                        static_cast<double>(header.PresentationTime.Time) *
                        header.PresentationTime.Numerator /
                        header.PresentationTime.Denominator * 1e-7;
                    driver_time_accumulator_ = abs_sec;
                }
            }

            const BYTE* p = static_cast<const BYTE*>(header.Data);
            const BYTE* const end = p + header.DataUsed;

            if (auto* cb = direct_callback_.load(std::memory_order_acquire)) {
                void* const user_data = direct_callback_user_data_.load(std::memory_order_acquire);

                while (p < end) {
                    if (p + sizeof(KSMUSICFORMAT) > end) break;
                    const auto* fmt = reinterpret_cast<const KSMUSICFORMAT*>(p);
                    const DWORD byte_count = fmt->ByteCount;

                    const BYTE* const payload = p + sizeof(KSMUSICFORMAT);
                    if (byte_count == 0 || (payload > end || byte_count > static_cast<DWORD>(end - payload))) break;

                    double final_msg_ts;
                    if constexpr (TMode == TimestampMode::QPC) {
                        final_msg_ts = buffer_qpc_ts - timestamp_baseline_;
                    }
                    else {
                        driver_time_accumulator_ += fmt->TimeDeltaMs * 0.001;
                        if (!driver_stream_baseline_set_.load(std::memory_order_relaxed)) {
                            driver_stream_baseline_ = driver_time_accumulator_;
                            driver_stream_baseline_set_.store(true, std::memory_order_relaxed);
                        }
                        final_msg_ts = driver_time_accumulator_ - driver_stream_baseline_;
                    }

                    cb(payload, byte_count, final_msg_ts, user_data);

                    const ULONG aligned_size = KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + byte_count, 8);
                    if (aligned_size == 0 || aligned_size > static_cast<ULONG>(end - p)) break;
                    p += aligned_size;
                }
            }
            else {
                if (!isUmpStream_) {
                    while (p < end) {
                        if (p + sizeof(KSMUSICFORMAT) > end) break;
                        const auto* fmt = reinterpret_cast<const KSMUSICFORMAT*>(p);
                        const DWORD byte_count = fmt->ByteCount;

                        const BYTE* const payload = p + sizeof(KSMUSICFORMAT);
                        if (byte_count == 0 || (payload > end || byte_count > static_cast<DWORD>(end - payload))) break;

                        double final_msg_ts;
                        if constexpr (TMode == TimestampMode::QPC) {
                            final_msg_ts = buffer_qpc_ts - timestamp_baseline_;
                        }
                        else {
                            driver_time_accumulator_ += fmt->TimeDeltaMs * 0.001;
                            if (!driver_stream_baseline_set_.load(std::memory_order_relaxed)) {
                                driver_stream_baseline_ = driver_time_accumulator_;
                                driver_stream_baseline_set_.store(true, std::memory_order_relaxed);
                            }
                            final_msg_ts = driver_time_accumulator_ - driver_stream_baseline_;
                        }

                        parser_.process(payload, byte_count, messageQueue_, info_.name, final_msg_ts, callback_signal_event_.get());

                        const ULONG aligned_size = KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + byte_count, 8);
                        if (aligned_size == 0 || aligned_size > static_cast<ULONG>(end - p)) break;
                        p += aligned_size;
                    }
                }
                else {
                    while (p < end) {
                        if (p + sizeof(KSMUSICFORMAT) > end) break;
                        const auto* fmt = reinterpret_cast<const KSMUSICFORMAT*>(p);
                        const DWORD byte_count = fmt->ByteCount;

                        const BYTE* const payload = p + sizeof(KSMUSICFORMAT);
                        if (byte_count == 0 || (payload > end || byte_count > static_cast<DWORD>(end - payload))) break;

                        double final_msg_ts;
                        if constexpr (TMode == TimestampMode::QPC) {
                            final_msg_ts = buffer_qpc_ts - timestamp_baseline_;
                        }
                        else {
                            driver_time_accumulator_ += fmt->TimeDeltaMs * 0.001;
                            if (!driver_stream_baseline_set_.load(std::memory_order_relaxed)) {
                                driver_stream_baseline_ = driver_time_accumulator_;
                                driver_stream_baseline_set_.store(true, std::memory_order_relaxed);
                            }
                            final_msg_ts = driver_time_accumulator_ - driver_stream_baseline_;
                        }

                        ump_parser_.process(payload, byte_count, umpMessageQueue_, info_.name, final_msg_ts, ump_callback_signal_event_.get());

                        const ULONG aligned_size = KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + byte_count, 8);
                        if (aligned_size == 0 || aligned_size > static_cast<ULONG>(end - p)) break;
                        p += aligned_size;
                    }
                }
            }
        }
        void setPinState(KSSTATE state) {
            KSPROPERTY p{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE,
                         KSPROPERTY_TYPE_SET };
            DWORD br = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &p, sizeof(p), &state,
                sizeof(state), &br, nullptr) &&
                state != KSSTATE_STOP)
                throw KsMidiError("Failed to set pin state",
                    static_cast<HRESULT>(GetLastError()));
        }

        mutable std::mutex mutex_;
        LockFreeSPSCQueue<MidiMessage> messageQueue_;
        LockFreeSPSCQueue<ump::UmpMessage> umpMessageQueue_;
        LockFreeSPSCQueue<KsMidiError> errorQueue_;
        MessageCallback message_callback_;
        std::thread poller_thread_;
        std::atomic<bool> stop_polling_{ true };
        UmpCallback ump_callback_;
        std::thread ump_poller_thread_;
        std::atomic<bool> stop_ump_polling_{ true };
        std::atomic<DirectMessageCallback> direct_callback_{ nullptr };
        std::atomic<void*> direct_callback_user_data_{ nullptr };
        ErrorCallback error_callback_;
        std::atomic<bool> stop_flag_{ true };
        internal::UniqueHandle filter_, pin_, callback_signal_event_,
            ump_callback_signal_event_;
        DeviceInfo info_;
        Settings settings_;
        std::thread reader_thread_;
        internal::MidiParser parser_;
        internal::UmpParser ump_parser_;
        bool isUmpStream_ = false;
        double perf_freq_reciprocal_{ 0.0 };  
        double timestamp_baseline_{ 0.0 };
        std::atomic<bool> baseline_is_set_{ false };
        double driver_time_accumulator_{ 0.0 };
        double driver_stream_baseline_{ 0.0 };
        std::atomic<bool> driver_stream_baseline_set_{ false };
       
    };

    MidiIn::MidiIn() = default;
    MidiIn::~MidiIn() noexcept {
        if (pimpl_) {
            try {
                pimpl_->closePort();
            }
            catch (...) {
            }
        }
    }
    MidiIn::MidiIn(MidiIn&& other) noexcept
        : pimpl_(std::move(other.pimpl_)), settings_(other.settings_) {
        other.pimpl_ = nullptr;
    }
    MidiIn& MidiIn::operator=(MidiIn&& other) noexcept {
        if (this != &other) {
            pimpl_ = std::move(other.pimpl_);
            settings_ = other.settings_;
            other.pimpl_ = nullptr;
        }
        return *this;
    }

    void MidiIn::openPort(unsigned int portNumber) {
        openPort(portNumber, settings_);
    }

    void MidiIn::openPort(unsigned int portNumber, const Settings& settings) {
        if (pimpl_) {
            pimpl_->closePort();
        }
        settings_ = settings;
        auto is_pow2 = [](size_t n) { return n != 0 && (n & (n - 1)) == 0; };
        if (!is_pow2(settings_.messageQueueSize) ||
            !is_pow2(settings_.umpMessageQueueSize) ||
            !is_pow2(settings_.errorQueueSize))
            throw KsMidiError("Queue sizes must be a power of two.", E_INVALIDARG);

        switch (settings_.timestampMode) {
        case TimestampMode::None:
            pimpl_ = std::make_unique<MidiInImpl<TimestampMode::None>>(settings_);
            break;
        case TimestampMode::Driver:
            pimpl_ = std::make_unique<MidiInImpl<TimestampMode::Driver>>(settings_);
            break;
        default:
            pimpl_ = std::make_unique<MidiInImpl<TimestampMode::QPC>>(settings_);
            break;
        }
        pimpl_->openPort(portNumber);
    }
    void MidiIn::closePort() {
        if (pimpl_) pimpl_->closePort();
    }
    bool MidiIn::isPortOpen() const noexcept {
        return pimpl_ ? pimpl_->isPortOpen() : false;
    }
    bool MidiIn::isUmpStream() const noexcept {
        return pimpl_ ? pimpl_->isUmpStream() : false;
    }
    bool MidiIn::try_pop_message(MidiMessage& m) noexcept {
        return pimpl_ ? pimpl_->try_pop_message(m) : false;
    }
    std::optional<MidiMessage> MidiIn::pop_message() noexcept {
        return pimpl_ ? pimpl_->pop_message() : std::nullopt;
    }
    void MidiIn::setCallback(MessageCallback cb) {
        if (pimpl_) pimpl_->setCallback(std::move(cb));
    }
    void MidiIn::cancelCallback() {
        if (pimpl_) pimpl_->cancelCallback();
    }
    bool MidiIn::try_pop_ump_message(ump::UmpMessage& m) noexcept {
        return pimpl_ ? pimpl_->try_pop_ump_message(m) : false;
    }
    std::optional<ump::UmpMessage> MidiIn::pop_ump_message() noexcept {
        return pimpl_ ? pimpl_->pop_ump_message() : std::nullopt;
    }
    void MidiIn::setUmpCallback(UmpCallback cb) {
        if (pimpl_) pimpl_->setUmpCallback(std::move(cb));
    }
    void MidiIn::cancelUmpCallback() {
        if (pimpl_) pimpl_->cancelUmpCallback();
    }
    bool MidiIn::try_pop_error(KsMidiError& e) noexcept {
        return pimpl_ ? pimpl_->try_pop_error(e) : false;
    }
    std::optional<KsMidiError> MidiIn::pop_error() noexcept {
        return pimpl_ ? pimpl_->pop_error() : std::nullopt;
    }
    void MidiIn::setErrorCallback(ErrorCallback cb) {
        if (pimpl_) pimpl_->setErrorCallback(std::move(cb));
    }
    void MidiIn::setDirectCallback(DirectMessageCallback cb, void* ud) {
        if (pimpl_) pimpl_->setDirectCallback(cb, ud);
    }
    void MidiIn::cancelDirectCallback() {
        if (pimpl_) pimpl_->cancelDirectCallback();
    }
    void MidiIn::ignoreTypes(bool s, bool t, bool n) {
        if (pimpl_ && pimpl_->isPortOpen()) {
            throw KsMidiError("Cannot change ignore settings while port is open.",
                E_ACCESSDENIED);
        }
        settings_.ignoreSysex = s;
        settings_.ignoreTime = t;
        settings_.ignoreSense = n;
    }

}  // namespace ksmidi
