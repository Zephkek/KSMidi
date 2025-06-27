/*
    KSMidi Core Implementation – KSMidi.cpp
    ---------------------------------------
    Author: Mohamed Maatallah
    Date: June 27, 2025

    This is the full internal implementation of the KSMidi library,
    responsible for interfacing directly with Windows Kernel Streaming (KS)
    to achieve low latency for MIDI input/output.
*/

#include "KSMidi.h"
#include <setupapi.h>
#include <initguid.h>
#include <ks.h>
#include <ksmedia.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <mutex>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ksuser.lib")

// Aligns a value up to the nearest alignment boundary.
#define KS_ALIGN_UP(v, a) (((v) + (a) - 1) & ~((a) - 1))

#ifdef KSMIDI_DEBUG
#   include <iostream>
#   define TRACE(x) do { std::wostringstream _os; _os << L"[KSMIDI] " << x << L'\n'; OutputDebugStringW(_os.str().c_str()); } while(0)
#else
#   define TRACE(x) do {} while(0)
#endif

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

        class MidiParser {
        public:
            struct Config {
                std::atomic<bool> ignoreSysex{ true };
                std::atomic<bool> ignoreTime{ true };
                std::atomic<bool> ignoreSense{ true };
                std::atomic<size_t> sysexChunkSize{ 1024 };
            };

            void process(const BYTE* data, DWORD size, LockFreeSPSCQueue<MidiMessage, 256>& queue, const std::string& sourceName, double timestamp, HANDLE eventToSignal) {
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

            Config config;

        private:
            bool parseByte(BYTE byte, LockFreeSPSCQueue<MidiMessage, 256>& queue, const std::string& sourceName, double timestamp) {
                if (state_ == State::SysEx) {
                    if (byte == 0xF7) { // End of SysEx
                        if (!config.ignoreSysex.load(std::memory_order_relaxed)) {
                            message_.push_back(byte);
                            queue.try_push({ timestamp, message_, sourceName, false });
                        }
                        state_ = State::Idle;
                        runningStatus_ = 0;
                        return !config.ignoreSysex.load(std::memory_order_relaxed);
                    }
                    else {
                        message_.push_back(byte);
                        size_t chunkSize = config.sysexChunkSize.load(std::memory_order_relaxed);
                        if (chunkSize > 0 && message_.size() >= chunkSize) {
                            if (!config.ignoreSysex.load(std::memory_order_relaxed)) {
                                queue.try_push({ timestamp, message_, sourceName, true });
                                message_.clear();
                                return true;
                            }
                            message_.clear();
                        }
                    }
                    return false;
                }

                if (byte >= 0xF8) { // Real-time messages
                    if ((!config.ignoreTime.load(std::memory_order_relaxed) && byte <= 0xFB) || (!config.ignoreSense.load(std::memory_order_relaxed) && byte >= 0xFE)) {
                        queue.try_push({ timestamp, {byte}, sourceName });
                        return true;
                    }
                    return false;
                }

                if (byte >= 0x80) { // Status byte
                    message_.clear();
                    message_.push_back(byte);
                    bytesNeeded_ = bytesForStatus(byte);
                    state_ = (bytesNeeded_ > 0) ? State::ExpectData : State::Idle;
                    if (byte == 0xF0) {
                        state_ = State::SysEx;
                        return false;
                    }
                    return (bytesNeeded_ == 0) ? handleCompleteMessage(queue, sourceName, timestamp) : false;
                }
                else { // Data byte
                    if (state_ == State::Idle) { // Assuming running status
                        if (runningStatus_ == 0) return false; // Ignore stray data byte
                        message_.clear();
                        message_.push_back(runningStatus_);
                        bytesNeeded_ = bytesForStatus(runningStatus_);
                        state_ = State::ExpectData;
                    }
                    message_.push_back(byte);
                    if (message_.size() == (size_t)bytesNeeded_ + 1) {
                        if ((message_[0] & 0xF0) != 0xF0) {
                            runningStatus_ = message_[0];
                        }
                        state_ = State::Idle;
                        return handleCompleteMessage(queue, sourceName, timestamp);
                    }
                }
                return false;
            }

            bool handleCompleteMessage(LockFreeSPSCQueue<MidiMessage, 256>& queue, const std::string& sourceName, double timestamp) {
                BYTE status = message_[0];
                bool pushed = false;
                if (status >= 0xF0) { // System Common messages
                    if ((!config.ignoreTime.load(std::memory_order_relaxed) && (status == 0xF1 || status == 0xF3)) ||
                        (!config.ignoreSense.load(std::memory_order_relaxed) && status == 0xF6)) {
                        pushed = queue.try_push({ timestamp, message_, sourceName });
                    }
                }
                else { // Channel messages
                    pushed = queue.try_push({ timestamp, message_, sourceName });
                }
                return pushed;
            }

            static int bytesForStatus(BYTE status) {
                BYTE highNibble = status & 0xF0;
                if (highNibble == 0xC0 || highNibble == 0xD0 || status == 0xF1 || status == 0xF3) return 1;
                if (highNibble >= 0x80 && highNibble <= 0xE0 && highNibble != 0xC0 && highNibble != 0xD0 || status == 0xF2) return 2;
                return 0; // Single-byte messages (0xF6) or SysEx start (0xF0)
            }

            enum class State { Idle, ExpectData, SysEx };
            State state_{ State::Idle };
            std::vector<BYTE> message_;
            BYTE runningStatus_ = 0;
            int bytesNeeded_ = 0;
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
                        if (isPinMidi(filter.get(), pinId, flow)) {
                            devices.push_back({ (unsigned int)devices.size(), getFriendlyName(devInfo.get(), &ifd), detail->DevicePath, pinId, getAvailableInstances(filter.get(), pinId) > 0 });
                        }
                    }
                }
                return devices;
            }

        private:
            static bool isPinMidi(HANDLE filter, DWORD pinId, KSPIN_DATAFLOW desiredFlow) {
                KSP_PIN pinFlowProp{ {KSPROPSETID_Pin, KSPROPERTY_PIN_DATAFLOW, KSPROPERTY_TYPE_GET}, pinId, 0 };
                KSPIN_DATAFLOW flow;
                DWORD bytesReturned = 0;
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinFlowProp, sizeof(pinFlowProp), &flow, sizeof(flow), &bytesReturned, nullptr) || flow != desiredFlow) {
                    return false;
                }

                KSP_PIN pinRangeProp{ {KSPROPSETID_Pin, KSPROPERTY_PIN_DATARANGES, KSPROPERTY_TYPE_GET}, pinId, 0 };
                ULONG size = 0;
                DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp, sizeof(pinRangeProp), nullptr, 0, &size, nullptr);
                if (size == 0) return false;

                std::vector<BYTE> buffer(size);
                if (!DeviceIoControl(filter, IOCTL_KS_PROPERTY, &pinRangeProp, sizeof(pinRangeProp), buffer.data(), size, &bytesReturned, nullptr)) return false;

                auto* multipleItem = reinterpret_cast<PKSMULTIPLE_ITEM>(buffer.data());
                auto* dataRange = reinterpret_cast<PKSDATARANGE>(multipleItem + 1);
                for (ULONG i = 0; i < multipleItem->Count; ++i) {
                    if (IsEqualGUID(dataRange->MajorFormat, KSDATAFORMAT_TYPE_MUSIC) && IsEqualGUID(dataRange->SubFormat, KSDATAFORMAT_SUBTYPE_MIDI)) {
                        return true;
                    }
                    dataRange = reinterpret_cast<PKSDATARANGE>(reinterpret_cast<PBYTE>(dataRange) + KS_ALIGN_UP(dataRange->FormatSize, 8));
                }
                return false;
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
    } // namespace internal



    KsMidiError::KsMidiError(const std::string& what, HRESULT code) : std::runtime_error(what + internal::FormatWinError(code)), code_(code) {}
    HRESULT KsMidiError::code() const noexcept { return code_; }

    unsigned int Api::getPortCountIn() { return internal::DeviceEnumerator::enumerate(KSCATEGORY_CAPTURE, KSPIN_DATAFLOW_OUT).size(); }
    unsigned int Api::getPortCountOut() { return internal::DeviceEnumerator::enumerate(KSCATEGORY_RENDER, KSPIN_DATAFLOW_IN).size(); }

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

    // --- MidiOut Implementation ---

    class MidiOut::MidiOutImpl {
        friend class MidiOut;
    public:
        ~MidiOutImpl() noexcept { closePort(); }

        void openPort(unsigned int portNumber) {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            closePort();

            try {
                DeviceInfo info = Api::getPortInfoOut(portNumber);
                if (!info.isAvailable) throw KsMidiError("Output port '" + info.name + "' is not available.", E_ACCESSDENIED);

                filter_.reset(CreateFileW(info.path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
                if (!filter_ || filter_.get() == INVALID_HANDLE_VALUE) throw KsMidiError("Failed to open device filter", static_cast<HRESULT>(GetLastError()));

                const size_t connectSize = sizeof(KSPIN_CONNECT) + sizeof(KSDATAFORMAT);
                std::vector<BYTE> connectBuffer(connectSize);
                auto* connect = reinterpret_cast<PKSPIN_CONNECT>(connectBuffer.data());
                auto* dataFormat = reinterpret_cast<PKSDATAFORMAT>(connect + 1);

                connect->Interface = { KSINTERFACESETID_Standard, KSINTERFACE_STANDARD_STREAMING, 0 };
                connect->Medium = { KSMEDIUMSETID_Standard, 0, 0 };
                connect->PinId = info.pinId;
                connect->PinToHandle = nullptr;
                connect->Priority = { KSPRIORITY_NORMAL, 1 };
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_MIDI, KSDATAFORMAT_SPECIFIER_NONE };

                HANDLE rawPinHandle = nullptr;
                HRESULT hr = KsCreatePin(filter_.get(), connect, GENERIC_WRITE, &rawPinHandle);
                if (FAILED(hr)) throw KsMidiError("Failed to create output pin.", hr);

                pin_.reset(rawPinHandle);
                ensurePinStopped();
                setPinState(KSSTATE_ACQUIRE);
                setPinState(KSSTATE_RUN);
                writeBuffer_.resize(2048);
            }
            catch (...) {
                if (pin_) { try { setPinState(KSSTATE_STOP); } catch (const KsMidiError&) {} }
                pin_.reset();
                filter_.reset();
                throw;
            }
        }

        void closePort() {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!pin_) return;
            ensurePinStopped();
            pin_.reset();
            filter_.reset();
        }

        void sendMessageImpl(const BYTE* message, size_t size) {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
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
        void setPinState(KSSTATE state) {
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_SET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &state, sizeof(state), &bytesReturned, nullptr)) {
                if (state != KSSTATE_STOP) throw KsMidiError("Failed to set pin state", static_cast<HRESULT>(GetLastError()));
            }
        }

        void ensurePinStopped() {
            if (!pin_) return;
            KSSTATE current = KSSTATE_STOP;
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_GET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &current, sizeof(current), &bytesReturned, nullptr) || current != KSSTATE_STOP) {
                try { setPinState(KSSTATE_STOP); } catch (const KsMidiError&) {}
            }
        }

        mutable std::recursive_mutex mutex_;
        internal::UniqueHandle filter_, pin_;
        std::vector<BYTE> writeBuffer_;
    };

    MidiOut::MidiOut() : pimpl_(std::make_unique<MidiOutImpl>()) {}
    MidiOut::~MidiOut() noexcept { try { pimpl_->closePort(); } catch (...) {} }
    MidiOut::MidiOut(MidiOut&&) noexcept = default;
    MidiOut& MidiOut::operator=(MidiOut&&) noexcept = default;
    void MidiOut::openPort(unsigned int portNumber) { pimpl_->openPort(portNumber); }
    void MidiOut::closePort() { pimpl_->closePort(); }
    bool MidiOut::isPortOpen() const noexcept { std::lock_guard<std::recursive_mutex> lock(pimpl_->mutex_); return pimpl_ && pimpl_->pin_; }
    void MidiOut::sendMessage(const std::vector<BYTE>& message) { pimpl_->sendMessageImpl(message.data(), message.size()); }
    void MidiOut::sendMessage(const BYTE* message, size_t size) { pimpl_->sendMessageImpl(message, size); }



    class MidiIn::MidiInImpl {
        friend class MidiIn;
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
        MidiInImpl() = default;
        ~MidiInImpl() noexcept { closePort(); }

        void openPort(unsigned int portNumber, const MidiIn::Settings& settings) {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (settings.bufferCount < 2) throw KsMidiError("Buffer count must be at least 2.", E_INVALIDARG);
            closePort();

            try {
                settings_ = settings;
                info_ = Api::getPortInfoIn(portNumber);
                if (!info_.isAvailable) throw KsMidiError("Input port '" + info_.name + "' is not available.", E_ACCESSDENIED);

                callback_signal_event_.reset(CreateEvent(nullptr, FALSE, FALSE, nullptr));
                if (!callback_signal_event_) throw KsMidiError("Failed to create callback event.", static_cast<HRESULT>(GetLastError()));

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
                *dataFormat = { sizeof(KSDATAFORMAT), 0, 0, 0, KSDATAFORMAT_TYPE_MUSIC, KSDATAFORMAT_SUBTYPE_MIDI, KSDATAFORMAT_SPECIFIER_NONE };

                HANDLE rawPinHandle = nullptr;
                HRESULT hr = KsCreatePin(filter_.get(), connect, GENERIC_READ, &rawPinHandle);
                if (FAILED(hr)) throw KsMidiError("Failed to create input pin.", hr);

                pin_.reset(rawPinHandle);
                ensurePinStopped();
                setPinState(KSSTATE_ACQUIRE);
                setPinState(KSSTATE_RUN);

                parser_.config.sysexChunkSize = settings_.sysexChunkSize;
                QueryPerformanceFrequency(&perf_freq_);
                stop_flag_ = false;
                reader_thread_ = std::thread(&MidiInImpl::readerLoop, this);
            }
            catch (...) {
                stop_flag_ = true;
                if (pin_) { try { setPinState(KSSTATE_STOP); } catch (const KsMidiError&) {} }
                pin_.reset();
                filter_.reset();
                callback_signal_event_.reset();
                throw;
            }
        }

        void closePort() {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            stop_flag_ = true;
            cancelCallback();

            if (pin_) CancelIoEx(pin_.get(), nullptr);
            if (reader_thread_.joinable()) reader_thread_.join();

            if (pin_) ensurePinStopped();
            pin_.reset();
            filter_.reset();
            callback_signal_event_.reset();
        }

        void setCallback(MessageCallback callback) {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            cancelCallback();
            message_callback_ = std::move(callback);
            if (message_callback_) {
                stop_polling_ = false;
                poller_thread_ = std::thread(&MidiInImpl::pollingLoop, this);
            }
        }

        void cancelCallback() {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!poller_thread_.joinable()) return;

            stop_polling_ = true;
            if (callback_signal_event_) SetEvent(callback_signal_event_.get());

            poller_thread_.join();
            message_callback_ = nullptr;
        }

        void ignoreTypes(bool sysex, bool time, bool sense) {
            parser_.config.ignoreSysex = sysex;
            parser_.config.ignoreTime = time;
            parser_.config.ignoreSense = sense;
        }

    private:
        void pollingLoop() {
            TRACE(L"Callback poller thread started.");
            MidiMessage msg;
            KsMidiError err;
            while (!stop_polling_) {
                WaitForSingleObject(callback_signal_event_.get(), INFINITE);
                if (stop_polling_) break;

                while (messageQueue_.try_pop(msg)) {
                    if (message_callback_) message_callback_(msg);
                }
                while (errorQueue_.try_pop(err)) {
                    if (error_callback_) error_callback_(err);
                }
            }
            TRACE(L"Callback poller thread exiting.");
        }

        void readerLoop() {
            TRACE(L"I/O reader thread started.");
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
            TRACE(L"I/O reader thread exiting.");
        }

        bool queueRead(ReadRequest& req) {
            ResetEvent(req.event.get());
            req.header.DataUsed = 0;
            // not used, but won't work without them.. keep windows happy
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

        void processData(const KSSTREAM_HEADER& header) {
            const BYTE* current = static_cast<const BYTE*>(header.Data);
            DWORD bytesToProcess = header.DataUsed;
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            double timestamp = static_cast<double>(now.QuadPart) / perf_freq_.QuadPart;

            while (bytesToProcess >= sizeof(KSMUSICFORMAT)) {
                auto* musicHeader = reinterpret_cast<const KSMUSICFORMAT*>(current);
                if (musicHeader->ByteCount > 0 && bytesToProcess >= sizeof(KSMUSICFORMAT) + musicHeader->ByteCount) {
                    parser_.process(current + sizeof(KSMUSICFORMAT), musicHeader->ByteCount, messageQueue_, info_.name, timestamp, callback_signal_event_.get());
                }
                DWORD alignedSize = KS_ALIGN_UP(sizeof(KSMUSICFORMAT) + musicHeader->ByteCount, 8);
                if (alignedSize == 0 || alignedSize > bytesToProcess) break;
                current += alignedSize;
                bytesToProcess -= alignedSize;
            }
        }

        void setPinState(KSSTATE state) {
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_SET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &state, sizeof(state), &bytesReturned, nullptr)) {
                if (state != KSSTATE_STOP) throw KsMidiError("Failed to set pin state", static_cast<HRESULT>(GetLastError()));
            }
        }

        void ensurePinStopped() {
            if (!pin_) return;
            KSSTATE current = KSSTATE_STOP;
            KSPROPERTY prop{ KSPROPSETID_Connection, KSPROPERTY_CONNECTION_STATE, KSPROPERTY_TYPE_GET };
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(pin_.get(), IOCTL_KS_PROPERTY, &prop, sizeof(prop), &current, sizeof(current), &bytesReturned, nullptr) || current != KSSTATE_STOP) {
                try { setPinState(KSSTATE_STOP); } catch (const KsMidiError&) {}
            }
        }

        mutable std::recursive_mutex mutex_;
        LockFreeSPSCQueue<MidiMessage, 256> messageQueue_;
        LockFreeSPSCQueue<KsMidiError, 16> errorQueue_;
        MidiIn::MessageCallback message_callback_;
        MidiIn::ErrorCallback error_callback_;
        std::atomic<bool> stop_flag_{ true };
        std::atomic<bool> stop_polling_{ true };
        internal::UniqueHandle filter_, pin_;
        internal::UniqueHandle callback_signal_event_;
        DeviceInfo info_;
        MidiIn::Settings settings_;
        std::thread reader_thread_;
        std::thread poller_thread_;
        internal::MidiParser parser_;
        LARGE_INTEGER perf_freq_{};
    };

    MidiIn::MidiIn() : pimpl_(std::make_unique<MidiInImpl>()) {}
    MidiIn::~MidiIn() noexcept { try { pimpl_->closePort(); } catch (...) {} }
    MidiIn::MidiIn(MidiIn&&) noexcept = default;
    MidiIn& MidiIn::operator=(MidiIn&&) noexcept = default;
    void MidiIn::openPort(unsigned int portNumber, const Settings& settings) { pimpl_->openPort(portNumber, settings); }
    void MidiIn::closePort() { pimpl_->closePort(); }
    bool MidiIn::isPortOpen() const noexcept { std::lock_guard<std::recursive_mutex> lock(pimpl_->mutex_); return pimpl_ && !pimpl_->stop_flag_.load(std::memory_order_relaxed); }
    bool MidiIn::try_pop_message(MidiMessage& message) noexcept { return pimpl_->messageQueue_.try_pop(message); }
    bool MidiIn::try_pop_error(KsMidiError& error) noexcept { return pimpl_->errorQueue_.try_pop(error); }
    void MidiIn::setCallback(MessageCallback callback) { pimpl_->setCallback(std::move(callback)); }
    void MidiIn::cancelCallback() { pimpl_->cancelCallback(); }
    void MidiIn::setErrorCallback(ErrorCallback callback) { std::lock_guard<std::recursive_mutex> lock(pimpl_->mutex_); pimpl_->error_callback_ = std::move(callback); }
    void MidiIn::ignoreTypes(bool s, bool t, bool n) { pimpl_->ignoreTypes(s, t, n); }

} // namespace ksmidi
