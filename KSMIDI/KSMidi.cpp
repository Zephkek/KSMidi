/*
    KSMidi Core Implementation – KSMidi.cpp
    ---------------------------------------
    Author: Mohamed Maatallah
    Date: June 28, 2025 (The Final Form)
    Modification: Added full MIDI 2.0 / UMP support with a dedicated UMP parser and API.

    This is the full internal implementation of the KSMidi library,
    responsible for interfacing directly with Windows Kernel Streaming (KS)
    to achieve low latency for MIDI input/output.
*/

#include "KSMidi.h"
#include <setupapi.h>
#include <initguid.h>
#include <ks.h>
#include <ksmedia.h>
#include <avrt.h> // For MMCSS
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <array>
#include <utility>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ksuser.lib")
#pragma comment(lib, "avrt.lib") 


// Aligns a value up to the nearest alignment boundary.
#define KS_ALIGN_UP(v, a) (((v) + (a) - 1) & ~((a) - 1))

namespace ksmidi {
    namespace internal {

        struct HandleDeleter { void operator()(HANDLE h) const { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
        using UniqueHandle = std::unique_ptr<void, HandleDeleter>;
        struct DevInfoDeleter { void operator()(HDEVINFO h) const { if (h && h != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(h); } };
        using UniqueDevInfo = std::unique_ptr<std::remove_pointer_t<HDEVINFO>, DevInfoDeleter>;

        static std::string FormatWinError(HRESULT err) {
            char* msg = nullptr;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, nullptr);
            std::ostringstream os;
            os << " (0x" << std::hex << err << std::dec << ")";
            if (msg) {
                os << ": " << msg;
                LocalFree(msg);
            }
            return os.str();
        }

        // --- MIDI 1.0 Byte Stream Parser ---
        namespace {
            constexpr std::array<uint8_t, 256> kBytesNeeded = [] {
                std::array<uint8_t, 256> t{};
                for (int s = 0; s < 256; ++s) {
                    uint8_t b = 0;
                    const uint8_t nibble = s & 0xF0;
                    if (nibble == 0xC0 || nibble == 0xD0 || s == 0xF1 || s == 0xF3) b = 1;
                    else if ((nibble >= 0x80 && nibble <= 0xE0) || s == 0xF2) b = 2;
                    t[s] = b;
                }
                return t;
                }();
        }

        class MidiParser {
        public:
            struct Config {
                bool ignoreSysex{ true };
                bool ignoreTime{ true };
                bool ignoreSense{ true };
                size_t sysexChunkSize{ 1024 };
            };
            Config config;

            void process(const BYTE* data, DWORD size, LockFreeSPSCQueue<MidiMessage>& queue, const std::string& sourceName, double timestamp, HANDLE eventToSignal) {
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
            bool parseByte(BYTE byte, LockFreeSPSCQueue<MidiMessage>& queue, const std::string& sourceName, double timestamp) {
                if (state_ == State::SysEx) {
                    if (byte == 0xF7) {
                        if (!config.ignoreSysex) {
                            sysex_buffer_.push_back(byte);
                            MidiMessage msg{ timestamp, std::move(sysex_buffer_), sourceName, false };
                            queue.try_push(std::move(msg));
                            sysex_buffer_.clear();
                        }
                        state_ = State::Idle;
                        runningStatus_ = 0;
                        return !config.ignoreSysex;
                    }
                    else {
                        sysex_buffer_.push_back(byte);
                        size_t chunkSize = config.sysexChunkSize;
                        if (chunkSize > 0 && sysex_buffer_.size() >= chunkSize) {
                            if (!config.ignoreSysex) {
                                queue.try_push({ timestamp, sysex_buffer_, sourceName, true });
                                sysex_buffer_.clear();
                                sysex_buffer_.reserve(chunkSize);
                                return true;
                            }
                            sysex_buffer_.clear();
                        }
                    }
                    return false;
                }

                if (byte >= 0xF8) {
                    if ((!config.ignoreTime && byte <= 0xFB) || (!config.ignoreSense && byte >= 0xFE)) {
                        MidiMessage msg{ timestamp, {byte}, sourceName };
                        return queue.try_push(std::move(msg));
                    }
                    return false;
                }

                if (byte >= 0x80) {
                    message_len_ = 0;
                    message_buffer_[message_len_++] = byte;
                    bytesNeeded_ = kBytesNeeded[byte];
                    state_ = (bytesNeeded_ > 0) ? State::ExpectData : State::Idle;
                    if (byte == 0xF0) {
                        state_ = State::SysEx;
                        sysex_buffer_.clear();
                        if (config.sysexChunkSize > 0) sysex_buffer_.reserve(config.sysexChunkSize);
                        sysex_buffer_.push_back(byte);
                        return false;
                    }
                    return (bytesNeeded_ == 0) ? handleCompleteMessage(queue, sourceName, timestamp) : false;
                }
                else {
                    if (state_ == State::Idle) {
                        if (runningStatus_ == 0) return false;
                        message_len_ = 0;
                        message_buffer_[message_len_++] = runningStatus_;
                        bytesNeeded_ = kBytesNeeded[runningStatus_];
                        state_ = State::ExpectData;
                    }

                    if (message_len_ < sizeof(message_buffer_)) {
                        message_buffer_[message_len_++] = byte;
                    }

                    if (message_len_ == (size_t)bytesNeeded_ + 1) {
                        if ((message_buffer_[0] & 0xF0) != 0xF0) {
                            runningStatus_ = message_buffer_[0];
                        }
                        state_ = State::Idle;
                        return handleCompleteMessage(queue, sourceName, timestamp);
                    }
                }
                return false;
            }

            bool handleCompleteMessage(LockFreeSPSCQueue<MidiMessage>& queue, const std::string& sourceName, double timestamp) {
                BYTE status = message_buffer_[0];
                bool shouldPush = false;
                if (status >= 0xF0) {
                    if ((!config.ignoreTime && (status == 0xF1 || status == 0xF3)) ||
                        (!config.ignoreSense && status == 0xF6)) {
                        shouldPush = true;
                    }
                }
                else {
                    shouldPush = true;
                }

                if (shouldPush) {
                    MidiMessage msg;
                    msg.timestamp = timestamp;
                    msg.source = sourceName;
                    msg.bytes.assign(message_buffer_, message_buffer_ + message_len_);
                    return queue.try_push(std::move(msg));
                }
                return false;
            }

            enum class State { Idle, ExpectData, SysEx };
            State state_{ State::Idle };
            BYTE message_buffer_[32]{};
            size_t message_len_ = 0;
            std::vector<BYTE> sysex_buffer_;
            BYTE runningStatus_ = 0;
            int bytesNeeded_ = 0;
        };

        // --- MIDI 2.0 UMP Parser ---
        class UmpParser {
        public:
            void process(const BYTE* data, DWORD size, LockFreeSPSCQueue<ump::UmpMessage>& queue, const std::string& sourceName, double timestamp, HANDLE eventToSignal) {
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
                switch (messageType) {
                case 0x0: case 0x1: case 0x2: return 1;
                case 0x3: case 0x4: return 2;
                case 0x5: return 4;
                case 0x6: case 0x7: return 1; // Reserved 32-bit
                case 0x8: case 0x9: case 0xA: return 2; // Reserved 64-bit
                case 0xB: case 0xC: return 3; // Reserved 96-bit
                case 0xD: case 0xE: case 0xF: return 4; // Reserved 128-bit
                default: return 0; // Should not happen
                }
            }

            bool parseByte(BYTE byte, LockFreeSPSCQueue<ump::UmpMessage>& queue, const std::string& sourceName, double timestamp) {
                packetBuffer_[bytesReceived_++] = byte;

                if (state_ == State::AwaitingPacket) {
                    if (bytesReceived_ == 4) { // Received the first word
                        uint8_t mt = (packetBuffer_[0] >> 4) & 0x0F;
                        wordsExpected_ = getUmpPacketSizeInWords(mt);

                        if (wordsExpected_ == 1) {
                            return pushCompletePacket(queue, sourceName, timestamp);
                        }
                        else if (wordsExpected_ > 1 && wordsExpected_ <= 4) {
                            state_ = State::AwaitingData;
                        }
                        else { // Invalid message type
                            bytesReceived_ = 0;
                            wordsExpected_ = 0;
                        }
                    }
                }
                else { // AwaitingData
                    if (bytesReceived_ == (wordsExpected_ * 4)) {
                        return pushCompletePacket(queue, sourceName, timestamp);
                    }
                }
                return false;
            }

            bool pushCompletePacket(LockFreeSPSCQueue<ump::UmpMessage>& queue, const std::string& sourceName, double timestamp) {
                ump::UmpMessage msg;
                msg.timestamp = timestamp;
                msg.source = sourceName;
                msg.size_in_words = wordsExpected_;
                std::memcpy(msg.words.data(), packetBuffer_.data(), wordsExpected_ * 4);

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

        class DeviceEnumerator {
        public:
            static std::vector<DeviceInfo> enumerate(const GUID& category, KSPIN_DATAFLOW flow) {
                UniqueDevInfo devInfo(SetupDiGetClassDevs(&category, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
                if (!devInfo || devInfo.get() == INVALID_HANDLE_VALUE) {
                    throw KsMidiError("SetupDiGetClassDevs failed", static_cast<HRESULT>(GetLastError()));
                }

                std::vector<DeviceInfo> devices;
                SP_DEVICE_INTERFACE_DATA ifd{ sizeof(ifd) };
                for (DWORD i = 0; SetupDiEnumDeviceInterfaces(devInfo.get(), nullptr, &category, i, &ifd); ++i) {
                    DWORD neededBytes = 0;
                    SetupDiGetDeviceInterfaceDetailW(devInfo.get(), &ifd, nullptr, 0, &neededBytes, nullptr);
                    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;

                    std::vector<BYTE> detailBuffer(neededBytes);
                    auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(detailBuffer.data());
                    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

                    if (!SetupDiGetDeviceInterfaceDetailW(devInfo.get(), &ifd, detail, neededBytes, nullptr, nullptr)) continue;

                    UniqueHandle filter(CreateFileW(detail->DevicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
                    if (!filter || filter.get() == INVALID_HANDLE_VALUE) continue;

                    KSPROPERTY pinProp{ KSPROPSETID_Pin, KSPROPERTY_PIN_CTYPES, KSPROPERTY_TYPE_GET };
                    DWORD pinCount = 0, bytesReturned = 0;
                    if (!DeviceIoControl(filter.get(), IOCTL_KS_PROPERTY, &pinProp, sizeof(pinProp), &pinCount, sizeof(pinCount), &bytesReturned, nullptr)) continue;

                    for (DWORD pinId = 0; pinId < pinCount; ++pinId) {
                        auto support = getPinMidiSupport(filter.get(), pinId, flow);
                        if (support.first) { // Is it a MIDI pin?
                            devices.push_back({
                                (unsigned int)devices.size(),
                                getFriendlyName(devInfo.get(), &ifd),
                                detail->DevicePath,
                                pinId,
                                getAvailableInstances(filter.get(), pinId) > 0,
                                support.second // Does it support MIDI 2.0?
                                });
                        }
                    }
                }
                return devices;
            }

        private:
            static std::pair<bool, bool> getPinMidiSupport(HANDLE filter, DWORD pinId, KSPIN_DATAFLOW desiredFlow) {
                KSP_PIN pinFlowProp{ {KSPROPSETID_Pin, KSPROPERTY_PIN_DATAFLOW, KSPROPERTY_TYPE_GET}, pinId, 0 };
                KSPIN_DATAFLOW flow;
                DWORD bytesReturned = 0;
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinFlowProp, sizeof(pinFlowProp), &flow, sizeof(flow), &bytesReturned, nullptr) || flow != desiredFlow) {
                    return { false, false };
                }

                KSP_PIN pinRangeProp{ {KSPROPSETID_Pin, KSPROPERTY_PIN_DATARANGES, KSPROPERTY_TYPE_GET}, pinId, 0 };
                ULONG size = 0;
                DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp, sizeof(pinRangeProp), nullptr, 0, &size, nullptr);
                if (size == 0) return { false, false };

                std::vector<BYTE> buffer(size);
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp, sizeof(pinRangeProp), buffer.data(), size, &bytesReturned, nullptr)) return { false, false };

                bool supportsMidi1 = false;
                bool supportsMidi2 = false;

                auto* multipleItem = reinterpret_cast<PKSMULTIPLE_ITEM>(buffer.data());
                auto* dataRange = reinterpret_cast<PKSDATARANGE>(multipleItem + 1);
                for (ULONG i = 0; i < multipleItem->Count; ++i) {
                    if (IsEqualGUID(dataRange->MajorFormat, KSDATAFORMAT_TYPE_MUSIC)) {
                        if (IsEqualGUID(dataRange->SubFormat, KSDATAFORMAT_SUBTYPE_MIDI)) {
                            supportsMidi1 = true;
                        }
                        else if (IsEqualGUID(dataRange->SubFormat, KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET)) {
                            supportsMidi2 = true;
                        }
                    }
                    dataRange = reinterpret_cast<PKSDATARANGE>(reinterpret_cast<PBYTE>(dataRange) + KS_ALIGN_UP(dataRange->FormatSize, 8));
                }
                return { supportsMidi1 || supportsMidi2, supportsMidi2 };
            }

            static long getAvailableInstances(HANDLE filter, DWORD pinId) {
                KSP_PIN pinInstancesProp{ {KSPROPSETID_Pin, KSPROPERTY_PIN_CINSTANCES, KSPROPERTY_TYPE_GET}, pinId, 0 };
                KSPIN_CINSTANCES instances{};
                DWORD bytesReturned = 0;
                if (DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinInstancesProp, sizeof(pinInstancesProp), &instances, sizeof(instances), &bytesReturned, nullptr)) {
                    return instances.PossibleCount - instances.CurrentCount;
                }
                return 0;
            }

            static std::string getFriendlyName(HDEVINFO devInfo, SP_DEVICE_INTERFACE_DATA* ifd) {
                char name[256] = "Unknown Device";
                HKEY regKey = SetupDiOpenDeviceInterfaceRegKey(devInfo, ifd, 0, KEY_READ);
                if (regKey != INVALID_HANDLE_VALUE) {
                    WCHAR wName[256]{};
                    DWORD size = sizeof(wName);
                    if (RegQueryValueExW(regKey, L"FriendlyName", nullptr, nullptr, (LPBYTE)wName, &size) == ERROR_SUCCESS) {
                        WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, sizeof(name), nullptr, nullptr);
                    }
                    RegCloseKey(regKey);
                }
                return name;
            }
        };
    }



    KsMidiError::KsMidiError(std::string_view what, HRESULT code) : std::runtime_error(std::string(what) + internal::FormatWinError(code)), code_(code) {}
    HRESULT KsMidiError::code() const noexcept { return code_; }

    unsigned int Api::getPortCountIn() { return static_cast<unsigned int>(internal::DeviceEnumerator::enumerate(KSCATEGORY_CAPTURE, KSPIN_DATAFLOW_OUT).size()); }
    unsigned int Api::getPortCountOut() { return static_cast<unsigned int>(internal::DeviceEnumerator::enumerate(KSCATEGORY_RENDER, KSPIN_DATAFLOW_IN).size()); }

    DeviceInfo Api::getPortInfoIn(unsigned int portNumber) {
        auto devices = internal::DeviceEnumerator::enumerate(KSCATEGORY_CAPTURE, KSPIN_DATAFLOW_OUT);
        if (portNumber >= devices.size()) throw KsMidiError("Invalid input port number specified.", E_INVALIDARG);
        return devices[portNumber];
    }

    DeviceInfo Api::getPortInfoOut(unsigned int portNumber) {
        auto devices = internal::DeviceEnumerator::enumerate(KSCATEGORY_RENDER, KSPIN_DATAFLOW_IN);
        if (portNumber >= devices.size()) throw KsMidiError("Invalid output port number specified.", E_INVALIDARG);
        return devices[portNumber];
    }

    class MidiOut::MidiOutImpl {
        friend class MidiOut;
    public:
        ~MidiOutImpl() noexcept { closePort(); }

        void openPort(unsigned int portNumber) {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
            info_ = Api::getPortInfoOut(portNumber);
            if (!info_.isAvailable) throw KsMidiError("Output port '" + info_.name + "' is not available.", E_ACCESSDENIED);

            filter_.reset(CreateFileW(info_.path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
            if (!filter_ || filter_.get() == INVALID_HANDLE_VALUE) throw KsMidiError("Failed to open device filter", static_cast<HRESULT>(GetLastError()));

            const size_t connectSize = sizeof(KSPIN_CONNECT) + sizeof(KSDATAFORMAT);
            std::vector<BYTE> connectBuffer(connectSize);
            auto* connect = reinterpret_cast<PKSPIN_CONNECT>(connectBuffer.data());
            auto* dataFormat = reinterpret_cast<PKSDATAFORMAT>(connect + 1);

            connect->Interface = { KSINTERFACESETID_Standard, KSINTERFACE_STANDARD_STREAMING, 0 };
            connect->Medium = { KSMEDIUMSETID_Standard, 0, 0 };
            connect->PinId = info_.pinId;
            connect->PinToHandle = nullptr;
            connect->Priority = { KSPRIORITY_NORMAL, 1 };

            if (info_.supportsMidi2) {
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET, KSDATAFORMAT_SPECIFIER_NONE };
            }
            else {
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_MIDI, KSDATAFORMAT_SPECIFIER_NONE };
            }

            HANDLE rawPinHandle = nullptr;
            HRESULT hr = KsCreatePin(filter_.get(), connect, GENERIC_WRITE, &rawPinHandle);
            if (FAILED(hr)) throw KsMidiError("Failed to create output pin.", hr);

            pin_.reset(rawPinHandle);
            setPinState(KSSTATE_ACQUIRE);
            setPinState(KSSTATE_RUN);
            writeBuffer_.resize(2048);
        }

        void closePort() {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();
        }

        bool isUmpStream() const noexcept { return info_.supportsMidi2; }

        void sendMessageImpl(const BYTE* message, size_t size) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!pin_ || !message || size == 0) return;

            const DWORD payloadSize = sizeof(KSMUSICFORMAT) + static_cast<DWORD>(size);
            if (payloadSize > writeBuffer_.size()) throw KsMidiError("MIDI message exceeds internal buffer size.", E_OUTOFMEMORY);

            auto* musicHeader = reinterpret_cast<PKSMUSICFORMAT>(writeBuffer_.data());
            musicHeader->TimeDeltaMs = 0;
            musicHeader->ByteCount = static_cast<DWORD>(size);
            memcpy(writeBuffer_.data() + sizeof(KSMUSICFORMAT), message, size);

            KSSTREAM_HEADER streamHeader{};
            streamHeader.Size = sizeof(streamHeader);
            streamHeader.Data = writeBuffer_.data();
            streamHeader.FrameExtent = KS_ALIGN_UP(payloadSize, 8);
            streamHeader.DataUsed = streamHeader.FrameExtent;

            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_WRITE_STREAM, nullptr, 0, &streamHeader, sizeof(streamHeader), &bytesReturned, nullptr)) {
                throw KsMidiError("Failed to write to MIDI stream.", static_cast<HRESULT>(GetLastError()));
            }
        }

    private:
        void closePortImpl() {
            if (!pin_) return;
            try { setPinState(KSSTATE_STOP); }
            catch (const KsMidiError&) {}
            pin_.reset();
            filter_.reset();
            info_ = {};
        }

        void setPinState(KSSTATE state) {
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_SET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &state, sizeof(state), &bytesReturned, nullptr)) {
                if (state != KSSTATE_STOP) throw KsMidiError("Failed to set pin state", static_cast<HRESULT>(GetLastError()));
            }
        }

        mutable std::mutex mutex_;
        DeviceInfo info_;
        internal::UniqueHandle filter_, pin_;
        std::vector<BYTE> writeBuffer_;
    };

    MidiOut::MidiOut() : pimpl_(std::make_unique<MidiOutImpl>()) {}
    MidiOut::~MidiOut() noexcept { try { pimpl_->closePort(); } catch (...) {} }
    MidiOut::MidiOut(MidiOut&&) noexcept = default;
    MidiOut& MidiOut::operator=(MidiOut&&) noexcept = default;
    void MidiOut::openPort(unsigned int portNumber) { pimpl_->openPort(portNumber); }
    void MidiOut::closePort() { pimpl_->closePort(); }
    bool MidiOut::isPortOpen() const noexcept { std::lock_guard<std::mutex> lock(pimpl_->mutex_); return pimpl_ && pimpl_->pin_; }
    bool MidiOut::isUmpStream() const noexcept { return pimpl_ ? pimpl_->isUmpStream() : false; }
    void MidiOut::sendMessage(const std::vector<BYTE>& message) { pimpl_->sendMessageImpl(message.data(), message.size()); }
    void MidiOut::sendMessage(const BYTE* message, size_t size) { pimpl_->sendMessageImpl(message, size); }
    void MidiOut::sendMessage(const ump::UmpMessage& message) { pimpl_->sendMessageImpl(reinterpret_cast<const BYTE*>(message.words.data()), message.size_in_words * 4); }


    class MidiIn::MidiInImplBase {
    public:
        virtual ~MidiInImplBase() = default;
        virtual void openPort(unsigned int portNumber, const MidiIn::Settings& settings) = 0;
        virtual void closePort() = 0;
        virtual bool isPortOpen() const noexcept = 0;
        virtual bool isUmpStream() const noexcept = 0;
        virtual bool try_pop_message(MidiMessage& message) noexcept = 0;
        virtual std::optional<MidiMessage> pop_message() noexcept = 0;
        virtual void setCallback(MessageCallback callback) = 0;
        virtual void cancelCallback() = 0;
        virtual bool try_pop_ump_message(ump::UmpMessage& message) noexcept = 0;
        virtual std::optional<ump::UmpMessage> pop_ump_message() noexcept = 0;
        virtual void setUmpCallback(UmpCallback callback) = 0;
        virtual void cancelUmpCallback() = 0;
        virtual bool try_pop_error(KsMidiError& error) noexcept = 0;
        virtual std::optional<KsMidiError> pop_error() noexcept = 0;
        virtual void setDirectCallback(DirectMessageCallback callback, void* userData) = 0;
        virtual void cancelDirectCallback() = 0;
        virtual void setErrorCallback(ErrorCallback callback) = 0;
        virtual void ignoreTypes(bool s, bool t, bool n) = 0;
    };

    template<MidiIn::TimestampMode TMode>
    class MidiInImpl final : public MidiIn::MidiInImplBase {
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
        explicit MidiInImpl(const MidiIn::Settings& settings) :
            settings_(settings),
            messageQueue_(settings.messageQueueSize),
            umpMessageQueue_(settings.umpMessageQueueSize),
            errorQueue_(settings.errorQueueSize)
        {
            if (settings.bufferCount < 2) throw KsMidiError("Buffer count must be at least 2.", E_INVALIDARG);
            if (TMode == MidiIn::TimestampMode::QPC || TMode == MidiIn::TimestampMode::Driver) {
                QueryPerformanceFrequency(&perf_freq_);
            }
        }
        ~MidiInImpl() noexcept override { closePort(); }

        void openPort(unsigned int portNumber, const MidiIn::Settings& settings) override {
            std::lock_guard<std::mutex> lock(mutex_);
            closePortImpl();

            settings_ = settings;
            info_ = Api::getPortInfoIn(portNumber);
            isUmpStream_ = info_.supportsMidi2;

            if (!info_.isAvailable) throw KsMidiError("Input port '" + info_.name + "' is not available.", E_ACCESSDENIED);

            callback_signal_event_.reset(CreateEvent(nullptr, FALSE, FALSE, nullptr));
            ump_callback_signal_event_.reset(CreateEvent(nullptr, FALSE, FALSE, nullptr));

            filter_.reset(CreateFileW(info_.path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
            if (!filter_ || filter_.get() == INVALID_HANDLE_VALUE) throw KsMidiError("Failed to open device filter", static_cast<HRESULT>(GetLastError()));

            const size_t connectSize = sizeof(KSPIN_CONNECT) + sizeof(KSDATAFORMAT);
            std::vector<BYTE> connectBuffer(connectSize);
            auto* connect = reinterpret_cast<PKSPIN_CONNECT>(connectBuffer.data());
            auto* dataFormat = reinterpret_cast<PKSDATAFORMAT>(connect + 1);

            connect->Interface = { KSINTERFACESETID_Standard, KSINTERFACE_STANDARD_STREAMING, 0 };
            connect->Medium = { KSMEDIUMSETID_Standard, 0, 0 };
            connect->PinId = info_.pinId;
            connect->PinToHandle = nullptr;
            connect->Priority = { KSPRIORITY_NORMAL, 1 };

            if (isUmpStream_) {
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_UNIVERSALMIDIPACKET, KSDATAFORMAT_SPECIFIER_NONE };
            }
            else {
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_MIDI, KSDATAFORMAT_SPECIFIER_NONE };
            }

            HANDLE rawPinHandle = nullptr;
            HRESULT hr = KsCreatePin(filter_.get(), connect, GENERIC_READ, &rawPinHandle);
            if (FAILED(hr)) throw KsMidiError("Failed to create input pin.", hr);

            pin_.reset(rawPinHandle);
            setPinState(KSSTATE_ACQUIRE);
            setPinState(KSSTATE_RUN);
            parser_.config.ignoreSysex = settings_.ignoreSysex;
            parser_.config.ignoreTime = settings_.ignoreTime;
            parser_.config.ignoreSense = settings_.ignoreSense;
            parser_.config.sysexChunkSize = settings_.sysexChunkSize;
            stop_flag_ = false;
            reader_thread_ = std::thread(&MidiInImpl::readerLoop, this);
        }

        void closePort() override { std::lock_guard<std::mutex> lock(mutex_); closePortImpl(); }
        bool isPortOpen() const noexcept override { return !stop_flag_.load(std::memory_order_relaxed); }
        bool isUmpStream() const noexcept override { return isUmpStream_; }

        // MIDI 1.0 API
        bool try_pop_message(MidiMessage& message) noexcept override { return messageQueue_.try_pop(message); }
        std::optional<MidiMessage> pop_message() noexcept override { return messageQueue_.pop(); }
        void setCallback(MidiIn::MessageCallback callback) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelDirectCallbackImpl(); cancelUmpCallbackImpl(); cancelCallbackImpl();
            message_callback_ = std::move(callback);
            if (message_callback_) { stop_polling_ = false; poller_thread_ = std::thread(&MidiInImpl::pollingLoop, this); }
        }
        void cancelCallback() override { std::lock_guard<std::mutex> lock(mutex_); cancelCallbackImpl(); }

        // MIDI 2.0 API
        bool try_pop_ump_message(ump::UmpMessage& message) noexcept override { return umpMessageQueue_.try_pop(message); }
        std::optional<ump::UmpMessage> pop_ump_message() noexcept override { return umpMessageQueue_.pop(); }
        void setUmpCallback(MidiIn::UmpCallback callback) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelDirectCallbackImpl(); cancelCallbackImpl(); cancelUmpCallbackImpl();
            ump_callback_ = std::move(callback);
            if (ump_callback_) { stop_ump_polling_ = false; ump_poller_thread_ = std::thread(&MidiInImpl::umpPollingLoop, this); }
        }
        void cancelUmpCallback() override { std::lock_guard<std::mutex> lock(mutex_); cancelUmpCallbackImpl(); }

        // Common API
        bool try_pop_error(KsMidiError& error) noexcept override { return errorQueue_.try_pop(error); }
        std::optional<KsMidiError> pop_error() noexcept override { return errorQueue_.pop(); }
        void setDirectCallback(MidiIn::DirectMessageCallback callback, void* userData) override {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelCallbackImpl(); cancelUmpCallbackImpl();
            direct_callback_user_data_ = userData;
            direct_callback_.store(callback, std::memory_order_release);
        }
        void cancelDirectCallback() override { std::lock_guard<std::mutex> lock(mutex_); cancelDirectCallbackImpl(); }
        void setErrorCallback(MidiIn::ErrorCallback callback) override { std::lock_guard<std::mutex> lock(mutex_); error_callback_ = std::move(callback); }
        void ignoreTypes(bool s, bool t, bool n) override { parser_.config.ignoreSysex = s; parser_.config.ignoreTime = t; parser_.config.ignoreSense = n; }

    private:
        void closePortImpl() {
            if (stop_flag_.load(std::memory_order_relaxed) || !reader_thread_.joinable()) return;
            stop_flag_ = true;
            cancelCallbackImpl(); cancelUmpCallbackImpl(); cancelDirectCallbackImpl();
            if (pin_) CancelIoEx(pin_.get(), nullptr);
            if (reader_thread_.joinable()) reader_thread_.join();
            if (pin_) { try { setPinState(KSSTATE_STOP); } catch (const KsMidiError&) {} }
            pin_.reset(); filter_.reset(); info_ = {}; isUmpStream_ = false;
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
        void cancelDirectCallbackImpl() { direct_callback_.store(nullptr, std::memory_order_release); direct_callback_user_data_ = nullptr; }

        void pollingLoop() {
            while (!stop_polling_) {
                WaitForSingleObject(callback_signal_event_.get(), INFINITE);
                if (stop_polling_) break;
                while (auto msg = messageQueue_.pop()) { if (message_callback_) message_callback_(*msg); }
                while (auto err = errorQueue_.pop()) { if (error_callback_) error_callback_(*err); }
            }
        }

        void umpPollingLoop() {
            while (!stop_ump_polling_) {
                WaitForSingleObject(ump_callback_signal_event_.get(), INFINITE);
                if (stop_ump_polling_) break;
                while (auto msg = umpMessageQueue_.pop()) { if (ump_callback_) ump_callback_(*msg); }
                while (auto err = errorQueue_.pop()) { if (error_callback_) error_callback_(*err); }
            }
        }

        void readerLoop() {
            std::vector<std::unique_ptr<ReadRequest>> requests;
            std::vector<HANDLE> events;
            for (unsigned int i = 0; i < settings_.bufferCount; ++i) {
                requests.push_back(std::make_unique<ReadRequest>(settings_.bufferSize));
                events.push_back(requests.back()->event.get());
            }

            for (auto& req : requests) {
                if (!queueRead(*req)) {
                    stop_flag_ = true;
                    break;
                }
            }

            while (!stop_flag_) {
                DWORD waitResult = WaitForMultipleObjects((DWORD)events.size(), events.data(), FALSE, INFINITE);
                if (stop_flag_) break;

                if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + events.size()) {
                    ReadRequest& req = *requests[waitResult - WAIT_OBJECT_0];
                    DWORD bytesRead = 0;
                    if (GetOverlappedResult(pin_.get(), &req.overlapped, &bytesRead, FALSE) && bytesRead > 0) {
                        processData(req.header);
                    }
                    if (!stop_flag_) queueRead(req);
                }
                else {
                    errorQueue_.try_push({ "MIDI listener wait failed. Device may be disconnected.", static_cast<HRESULT>(GetLastError()) });
                    if (callback_signal_event_) SetEvent(callback_signal_event_.get());
                    break;
                }
            }
        }

        bool queueRead(ReadRequest& req) {
            ResetEvent(req.event.get());
            memset(req.data.data(), 0, req.data.size());
            req.header.DataUsed = 0;
            // keep le windows happy
            req.header.PresentationTime.Time = 0;
            req.header.PresentationTime.Numerator = 1;
            req.header.PresentationTime.Denominator = 1;
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_READ_STREAM, nullptr, 0, &req.header, sizeof(req.header), &bytesReturned, &req.overlapped)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    errorQueue_.try_push({ "A fatal stream read error occurred.", static_cast<HRESULT>(GetLastError()) });
                    if (callback_signal_event_) SetEvent(callback_signal_event_.get());
                    return false;
                }
            }
            return true;
        }

        void processData(const KSSTREAM_HEADER& header) noexcept {
            double ts = 0.0;
            if constexpr (TMode == MidiIn::TimestampMode::QPC) {
                LARGE_INTEGER now; QueryPerformanceCounter(&now);
                ts = static_cast<double>(now.QuadPart) / perf_freq_.QuadPart;
            }
            else if constexpr (TMode == MidiIn::TimestampMode::Driver) {
                ts = static_cast<double>(header.PresentationTime.Time) / 10'000'000.0;
            }

            const BYTE* p = static_cast<const BYTE*>(header.Data);
            const BYTE* const end = p + header.DataUsed;
            auto* const cb = direct_callback_.load(std::memory_order_acquire);

            if (cb) {
                // High-performance direct callback path
                void* const cbUser = direct_callback_user_data_;
                const BYTE* const lim = end - sizeof(KSMUSICFORMAT);
                while (p <= lim) {
                    const auto* fmt = reinterpret_cast<const KSMUSICFORMAT*>(p);
                    const DWORD bc = fmt->ByteCount;
                    const BYTE* payload = p + sizeof(KSMUSICFORMAT);
                    if (bc == 0 || payload + bc > end) break;
                    cb(payload, bc, ts, cbUser);
                    p += KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + bc, 8);
                }
            }
            else {
                // Standard, parsing callback path
                const BYTE* const lim = end - sizeof(KSMUSICFORMAT);
                while (p <= lim) {
                    const auto* fmt = reinterpret_cast<const KSMUSICFORMAT*>(p);
                    const DWORD bc = fmt->ByteCount;
                    const BYTE* payload = p + sizeof(KSMUSICFORMAT);
                    if (bc == 0 || payload + bc > end) break;

                    if (isUmpStream_) {
                        ump_parser_.process(payload, bc, umpMessageQueue_, info_.name, ts, ump_callback_signal_event_.get());
                    }
                    else {
                        parser_.process(payload, bc, messageQueue_, info_.name, ts, callback_signal_event_.get());
                    }

                    p += KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + bc, 8);
                }
            }
        }
        void setPinState(KSSTATE state) {
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_SET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &state, sizeof(state), &bytesReturned, nullptr)) {
                if (state != KSSTATE_STOP) throw KsMidiError("Failed to set pin state", static_cast<HRESULT>(GetLastError()));
            }
        }
        mutable std::mutex mutex_;
        LockFreeSPSCQueue<MidiMessage> messageQueue_;
        LockFreeSPSCQueue<ump::UmpMessage> umpMessageQueue_;
        LockFreeSPSCQueue<KsMidiError> errorQueue_;

        MidiIn::MessageCallback message_callback_;
        std::thread poller_thread_;
        std::atomic<bool> stop_polling_{ true };

        MidiIn::UmpCallback ump_callback_;
        std::thread ump_poller_thread_;
        std::atomic<bool> stop_ump_polling_{ true };

        std::atomic<MidiIn::DirectMessageCallback> direct_callback_{ nullptr };
        void* direct_callback_user_data_{ nullptr };

        MidiIn::ErrorCallback error_callback_;
        std::atomic<bool> stop_flag_{ true };
        internal::UniqueHandle filter_, pin_;
        internal::UniqueHandle callback_signal_event_;
        internal::UniqueHandle ump_callback_signal_event_;
        DeviceInfo info_;
        MidiIn::Settings settings_;
        std::thread reader_thread_;
        internal::MidiParser parser_;
        internal::UmpParser ump_parser_;
        bool isUmpStream_ = false;
        LARGE_INTEGER perf_freq_{};
    };

    MidiIn::MidiIn() = default;
    MidiIn::~MidiIn() noexcept { if (pimpl_) try { pimpl_->closePort(); } catch (...) {} }
    MidiIn::MidiIn(MidiIn&&) noexcept = default;
    MidiIn& MidiIn::operator=(MidiIn&&) noexcept = default;

    void MidiIn::openPort(unsigned int portNumber, const Settings& settings) {
        if (pimpl_) { pimpl_->closePort(); }
        auto is_power_of_two = [](size_t n) { return n != 0 && (n & (n - 1)) == 0; };
        if (!is_power_of_two(settings.messageQueueSize) || !is_power_of_two(settings.umpMessageQueueSize) || !is_power_of_two(settings.errorQueueSize)) {
            throw KsMidiError("Queue sizes must be a power of two.", E_INVALIDARG);
        }
        switch (settings.timestampMode) {
        case TimestampMode::None: pimpl_ = std::make_unique<MidiInImpl<TimestampMode::None>>(settings); break;
        case TimestampMode::Driver: pimpl_ = std::make_unique<MidiInImpl<TimestampMode::Driver>>(settings); break;
        default: pimpl_ = std::make_unique<MidiInImpl<TimestampMode::QPC>>(settings); break;
        }
        pimpl_->openPort(portNumber, settings);
    }

    void MidiIn::closePort() { if (pimpl_) pimpl_->closePort(); }
    bool MidiIn::isPortOpen() const noexcept { return pimpl_ ? pimpl_->isPortOpen() : false; }
    bool MidiIn::isUmpStream() const noexcept { return pimpl_ ? pimpl_->isUmpStream() : false; }
    bool MidiIn::try_pop_message(MidiMessage& message) noexcept { return pimpl_ ? pimpl_->try_pop_message(message) : false; }
    std::optional<MidiMessage> MidiIn::pop_message() noexcept { return pimpl_ ? pimpl_->pop_message() : std::nullopt; }
    void MidiIn::setCallback(MessageCallback callback) { if (pimpl_) pimpl_->setCallback(std::move(callback)); }
    void MidiIn::cancelCallback() { if (pimpl_) pimpl_->cancelCallback(); }
    bool MidiIn::try_pop_ump_message(ump::UmpMessage& message) noexcept { return pimpl_ ? pimpl_->try_pop_ump_message(message) : false; }
    std::optional<ump::UmpMessage> MidiIn::pop_ump_message() noexcept { return pimpl_ ? pimpl_->pop_ump_message() : std::nullopt; }
    void MidiIn::setUmpCallback(UmpCallback callback) { if (pimpl_) pimpl_->setUmpCallback(std::move(callback)); }
    void MidiIn::cancelUmpCallback() { if (pimpl_) pimpl_->cancelUmpCallback(); }
    bool MidiIn::try_pop_error(KsMidiError& error) noexcept { return pimpl_ ? pimpl_->try_pop_error(error) : false; }
    std::optional<KsMidiError> MidiIn::pop_error() noexcept { return pimpl_ ? pimpl_->pop_error() : std::nullopt; }
    void MidiIn::setErrorCallback(ErrorCallback callback) { if (pimpl_) pimpl_->setErrorCallback(std::move(callback)); }
    void MidiIn::setDirectCallback(DirectMessageCallback callback, void* userData) { if (pimpl_) pimpl_->setDirectCallback(callback, userData); }
    void MidiIn::cancelDirectCallback() { if (pimpl_) pimpl_->cancelDirectCallback(); }
    void MidiIn::ignoreTypes(bool s, bool t, bool n) { if (pimpl_) pimpl_->ignoreTypes(s, t, n); }

} // namespace ksmidi
