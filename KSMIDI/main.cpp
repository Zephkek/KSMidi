/*
    KSMidi Sample & Tests – main.cpp
    --------------------------------------
    Small testing app for lib functionality.
*/

#include "KSMidi.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <limits>
#include <mutex>
#include <condition_variable>
#include <numeric>
#include <cmath>
#include <conio.h>

std::mutex cout_mutex;


void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void pressEnterToContinue() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (std::cin.peek() == '\n') std::cin.ignore();
    std::cin.get();
}

void printHeader(const std::string& title) {
    clearScreen();
    std::cout << "========================================================\n"
        << "  KSMidi Test Suite: " << title << "\n"
        << "========================================================\n\n";
}


void printMidi1Message(const ksmidi::MidiMessage& msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << std::fixed << std::setprecision(6) << msg.timestamp << " | "
        << msg.source << " | ";

    if (msg.bytes.empty()) {
        std::cout << "Empty Message\n";
        return;
    }

    const unsigned char status = msg.bytes[0];
    const unsigned char high_nibble = status & 0xF0;
    const unsigned char channel = (status & 0x0F) + 1;

    switch (high_nibble) {
    case 0x80: std::cout << "Note Off   (Ch " << std::setw(2) << (int)channel << ", Key " << std::setw(3) << (int)msg.bytes[1] << ", Vel " << std::setw(3) << (int)msg.bytes[2] << ")\n"; break;
    case 0x90: std::cout << (msg.bytes.size() > 2 && msg.bytes[2] > 0 ? "Note On    " : "Note Off   ") << "(Ch " << std::setw(2) << (int)channel << ", Key " << std::setw(3) << (int)msg.bytes[1] << ", Vel " << std::setw(3) << (msg.bytes.size() > 2 ? (int)msg.bytes[2] : 0) << ")\n"; break;
    case 0xA0: std::cout << "Aftertouch (Ch " << std::setw(2) << (int)channel << ", Key " << std::setw(3) << (int)msg.bytes[1] << ", Pressure " << std::setw(3) << (int)msg.bytes[2] << ")\n"; break;
    case 0xB0: std::cout << "CC         (Ch " << std::setw(2) << (int)channel << ", Ctl " << std::setw(3) << (int)msg.bytes[1] << ", Val " << std::setw(3) << (int)msg.bytes[2] << ")\n"; break;
    case 0xC0: std::cout << "Prog Change(Ch " << std::setw(2) << (int)channel << ", Pgm " << std::setw(3) << (int)msg.bytes[1] << ")\n"; break;
    case 0xD0: std::cout << "Chan Press (Ch " << std::setw(2) << (int)channel << ", Pressure " << std::setw(3) << (int)msg.bytes[1] << ")\n"; break;
    case 0xE0: std::cout << "Pitch Bend (Ch " << std::setw(2) << (int)channel << ", Val " << std::setw(5) << ((int)(msg.bytes[2]) << 7 | msg.bytes[1]) << ")\n"; break;
    case 0xF0:
        if (msg.isSysExChunk) std::cout << "SysEx Chunk ("; else std::cout << "SysEx (";
        std::cout << msg.bytes.size() << " bytes)\n";
        break;
    default:
        std::cout << "System Msg (0x" << std::hex << (int)status << std::dec << "), Size: " << msg.bytes.size() << " bytes\n";
        break;
    }
}

void printUmpMessage(const ksmidi::ump::UmpMessage& msg) {
    using namespace ksmidi::ump;
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << std::fixed << std::setprecision(6) << msg.timestamp << " | "
        << msg.source << " | ";

    MessageType mt = getMessageType(msg);
    uint8_t group = getGroup(msg);
    std::cout << "UMP (Grp " << (int)group << ", MT 0x" << std::hex << (int)mt << std::dec << "): ";

    switch (mt) {
    case MessageType::MIDI2_CHANNEL_VOICE: {
        uint8_t status = getMidi2Status(msg);
        uint8_t ch = getMidi2Channel(msg);
        uint8_t note = getNoteNumber(msg);
        switch (status) {
        case 0x9: // Note On
            std::cout << "Note On   (Ch " << std::setw(2) << (int)ch + 1 << ", Note " << std::setw(3) << (int)note
                << ", Vel " << std::setw(5) << getMidi2Velocity(msg) << ", Attr " << (int)getAttributeType(msg) << ")\n";
            break;
        case 0x8: // Note Off
            std::cout << "Note Off  (Ch " << std::setw(2) << (int)ch + 1 << ", Note " << std::setw(3) << (int)note
                << ", Vel " << std::setw(5) << getMidi2Velocity(msg) << ", Attr " << (int)getAttributeType(msg) << ")\n";
            break;
        case 0xB: // CC
            std::cout << "CC        (Ch " << std::setw(2) << (int)ch + 1 << ", Idx " << std::setw(3) << (int)getMidi1Data1(msg)
                << ", Val " << std::setw(10) << getMidi2Data(msg) << ")\n";
            break;
            // Add other MIDI 2.0 messages as needed
        default:
            std::cout << "MIDI 2.0 CV Message (Status 0x" << std::hex << (int)status << std::dec << ")\n";
            break;
        }
        break;
    }
    case MessageType::MIDI1_CHANNEL_VOICE:
        std::cout << "MIDI 1.0 CV in UMP wrapper.\n";
        break;
    case MessageType::SYSTEM:
        std::cout << "System Common (Status 0x" << std::hex << (int)getStatus(msg) << std::dec << ")\n";
        break;
    case MessageType::UTILITY:
        std::cout << "Utility Message (Status 0x" << std::hex << (int)getStatus(msg) << std::dec << ")\n";
        break;
    default:
        std::cout << "Other UMP type. Size: " << (int)msg.size_in_words * 4 << " bytes\n";
        break;
    }
}

void printError(const ksmidi::KsMidiError& err) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cerr << "\n\n--- KSMIDI RUNTIME ERROR ---\n" << err.what() << "\n----------------------------\n\n";
}

int selectPort(bool isInput) {
    unsigned int portCount = isInput ? ksmidi::Api::getPortCountIn() : ksmidi::Api::getPortCountOut();
    if (portCount == 0) {
        std::cout << "No " << (isInput ? "input" : "output") << " ports found.\n";
        return -1;
    }

    std::cout << "Available " << (isInput ? "input" : "output") << " ports:\n";
    for (unsigned int i = 0; i < portCount; ++i) {
        auto info = isInput ? ksmidi::Api::getPortInfoIn(i) : ksmidi::Api::getPortInfoOut(i);
        std::cout << "  " << i << ": " << info.name
            << (info.supportsMidi2 ? " [UMP]" : "")
            << (info.isAvailable ? "" : " [UNAVAILABLE/IN USE]") << '\n';
    }

    std::cout << "\nChoose a port number: ";
    unsigned int port;
    std::cin >> port;
    if (std::cin.fail() || port >= portCount) {
        std::cout << "Invalid selection.\n";
        return -1;
    }
    auto info = isInput ? ksmidi::Api::getPortInfoIn(port) : ksmidi::Api::getPortInfoOut(port);
    if (!info.isAvailable) {
        std::cout << "Port is unavailable.\n";
        return -1;
    }
    return port;
}



void testDetailedPortScan() {
    printHeader("Detailed Port Scan");
    try {
        std::cout << "[ MIDI Input Ports ]\n";
        unsigned int inPorts = ksmidi::Api::getPortCountIn();
        if (inPorts == 0) {
            std::cout << "  No input ports found.\n";
        }
        else {
            for (unsigned int i = 0; i < inPorts; ++i) {
                auto info = ksmidi::Api::getPortInfoIn(i);
                std::cout << "  " << i << ": " << info.name << '\n'
                    << "     - Available: " << (info.isAvailable ? "Yes" : "No") << '\n'
                    << "     - UMP Capable: " << (info.supportsMidi2 ? "Yes" : "No") << '\n'
                    << "     - Pin ID: " << info.pinId << '\n'
                    << "     - Path: " << info.path.c_str() << '\n';
            }
        }

        std::cout << "\n[ MIDI Output Ports ]\n";
        unsigned int outPorts = ksmidi::Api::getPortCountOut();
        if (outPorts == 0) {
            std::cout << "  No output ports found.\n";
        }
        else {
            for (unsigned int i = 0; i < outPorts; ++i) {
                auto info = ksmidi::Api::getPortInfoOut(i);
                std::cout << "  " << i << ": " << info.name << '\n'
                    << "     - Available: " << (info.isAvailable ? "Yes" : "No") << '\n'
                    << "     - UMP Capable: " << (info.supportsMidi2 ? "Yes" : "No") << '\n'
                    << "     - Pin ID: " << info.pinId << '\n'
                    << "     - Path: " << info.path.c_str() << '\n';
            }
        }
    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
    }
    pressEnterToContinue();
}

void testMidiOut() {
    printHeader("MIDI Output Test");
    int port = selectPort(false);
    if (port == -1) { pressEnterToContinue(); return; }

    try {
        ksmidi::MidiOut midiOut;
        midiOut.openPort(port);
        auto info = ksmidi::Api::getPortInfoOut(port);
        std::cout << "Port '" << info.name << "' opened successfully. UMP support: " << (info.supportsMidi2 ? "Yes" : "No") << "\n";

        while (true) {
            printHeader("MIDI Output Test Menu");
            std::cout << "Port '" << info.name << "' is open.\n\n"
                << "--- MIDI 1.0 Messages ---\n"
                << "1: Send Note On/Off (Middle C)\n"
                << "2: Send CC #7 (Volume) Sweep\n"
                << "3: Send a large (4KB) SysEx message\n";
            if (info.supportsMidi2) {
                std::cout << "--- MIDI 2.0 (UMP) Messages ---\n"
                    << "4: Send UMP Note On/Off (16-bit velocity)\n"
                    << "5: Send UMP CC (32-bit value)\n";
            }
            std::cout << "\n0: Close port and return\n"
                << "Choice: ";
            int choice;
            std::cin >> choice;
            if (std::cin.fail()) { choice = -1; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }

            if (choice == 0) break;

            switch (choice) {
            case 1: {
                std::cout << "\nSending Note On (Ch 1, Key 60, Vel 100) for 1 second...\n";
                BYTE msg[] = { 0x90, 60, 100 };
                midiOut.sendMessage(msg, sizeof(msg));
                std::this_thread::sleep_for(std::chrono::seconds(1));
                msg[0] = 0x80; // Note Off
                midiOut.sendMessage(msg, sizeof(msg));
                std::cout << "Note Off sent.\n";
                break;
            }
            case 2: {
                std::cout << "\nSending CC#7 sweep from 0 to 127 on Ch 1...\n";
                BYTE msg[] = { 0xB0, 7, 0 };
                for (int i = 0; i <= 127; ++i) {
                    msg[2] = i;
                    midiOut.sendMessage(msg, sizeof(msg));
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                msg[2] = 0;
                midiOut.sendMessage(msg, sizeof(msg));
                std::cout << "Sweep complete.\n";
                break;
            }
            case 3: {
                std::cout << "\nSending a 4096-byte SysEx message...\n";
                std::vector<BYTE> sysex;
                sysex.reserve(4096);
                sysex.push_back(0xF0);
                for (int i = 0; i < 4094; ++i) sysex.push_back(i % 127);
                sysex.push_back(0xF7);
                midiOut.sendMessage(sysex);
                std::cout << "SysEx sent.\n";
                break;
            }
            case 4: {
                if (!info.supportsMidi2) { std::cout << "Port does not support UMP.\n"; break; }
                std::cout << "\nSending UMP Note On (Group 0, Ch 1, Key 60, Vel 50000) for 1 second...\n";
                auto msg_on = ksmidi::ump::makeNoteOn(0, 0, 60, 50000);
                midiOut.sendMessage(msg_on);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto msg_off = ksmidi::ump::makeNoteOff(0, 0, 60, 0);
                midiOut.sendMessage(msg_off);
                std::cout << "UMP Note Off sent.\n";
                break;
            }
            case 5: {
                if (!info.supportsMidi2) { std::cout << "Port does not support UMP.\n"; break; }
                std::cout << "\nSending UMP CC#7 sweep (32-bit) on Ch 1...\n";
                for (uint32_t i = 0; i <= 65535; i += 256) {
                    // Scale 0-65535 to 0-UINT32_MAX for demonstration
                    uint32_t val = (uint32_t)((double)i / 65535.0 * (double)UINT32_MAX);
                    auto msg = ksmidi::ump::makeControlChange(0, 0, 7, val);
                    midiOut.sendMessage(msg);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                std::cout << "UMP CC sweep complete.\n";
                break;
            }
            default: std::cout << "Invalid choice.\n"; break;
            }
            if (choice != 0) pressEnterToContinue();
        }
    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
        pressEnterToContinue();
    }
}

void testMidiIn() {
    printHeader("MIDI Input Test");
    int port = selectPort(true);
    if (port == -1) { pressEnterToContinue(); return; }

    try {
        ksmidi::MidiIn midiIn;
        auto info = ksmidi::Api::getPortInfoIn(port);
        midiIn.openPort(port);
        midiIn.setErrorCallback(&printError);

        while (true) {
            printHeader("MIDI Input Test Menu");
            std::cout << "Port '" << info.name << "' is open.\n\n"
                << "1: Real-time Monitor (Callback API)\n"
                << "2: Real-time Monitor (Manual Polling API)\n"
                << "3: Interactive Filter Test (ignoreTypes)\n"
                << "4: Error Handling Test (Unplug Device)\n"
                << "0: Close port and return\n"
                << "Choice: ";
            int choice;
            std::cin >> choice;
            if (std::cin.fail()) { choice = -1; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }

            if (choice == 0) break;

            if ((choice == 1 || choice == 4) && midiIn.isPortOpen()) {
                if (info.supportsMidi2) midiIn.setUmpCallback(&printUmpMessage);
                else midiIn.setCallback(&printMidi1Message);
            }

            switch (choice) {
            case 1: {
                printHeader("Callback Monitoring");
                std::cout << "Monitoring using " << (info.supportsMidi2 ? "UMP" : "MIDI 1.0") << " callback. Press any key to stop.\n\n";
                while (!_kbhit()) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }
                (void)_getch();
                break;
            }
            case 2: {
                printHeader("Manual Polling Monitoring");
                std::cout << "Monitoring using manual polling. Press any key to stop.\n\n";
                while (!_kbhit()) {
                    if (info.supportsMidi2) {
                        ksmidi::ump::UmpMessage msg;
                        while (midiIn.try_pop_ump_message(msg)) printUmpMessage(msg);
                    }
                    else {
                        ksmidi::MidiMessage msg;
                        while (midiIn.try_pop_message(msg)) printMidi1Message(msg);
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                (void)_getch();
                break;
            }
            case 3: { 
                printHeader("Interactive Filter Test");
                std::cout << "This test only applies to MIDI 1.0 message streams.\n"
                    << "Press 's' to toggle SysEx, 't' for Time, 'n' for Sense filters.\n"
                    << "Press any other key to stop.\n\n";

                midiIn.cancelCallback();
                midiIn.cancelUmpCallback();
                if (midiIn.isPortOpen()) midiIn.closePort();

                bool s = true, t = true, n = true;
                auto print_filters = [&](bool sysex, bool time, bool sense) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n--> Filters set: SysEx=" << (sysex ? "ON" : "OFF")
                        << " Time=" << (time ? "ON" : "OFF") << " Sense=" << (sense ? "ON" : "OFF") << " <--\n"
                        << "Monitoring... Press s/t/n to change or another key to exit.\n";
                    };

                midiIn.ignoreTypes(s, t, n);
                midiIn.openPort(port);
                midiIn.setCallback(&printMidi1Message);
                print_filters(s, t, n);

                while (true) {
                    if (_kbhit()) {
                        char c = _getch();
                        bool changed = false;
                        if (c == 's' || c == 'S') { s = !s; changed = true; }
                        else if (c == 't' || c == 'T') { t = !t; changed = true; }
                        else if (c == 'n' || c == 'N') { n = !n; changed = true; }

                        if (changed) {
                            // sequence the reconfiguration (cannot filter without closing the port first), will fix this later.
                            midiIn.closePort();
                            midiIn.ignoreTypes(s, t, n);
                            midiIn.openPort(port);
                            midiIn.setCallback(&printMidi1Message);
                            print_filters(s, t, n);
                        }
                        else {
                            break; 
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                if (!midiIn.isPortOpen()) midiIn.openPort(port);
                break;
            }
            case 4: {
                printHeader("Error Handling Test");
                std::cout << "Listening for messages. Please unplug the MIDI device now to trigger a fatal stream error...\n"
                    << "The error handler should report it. Press any key to stop.\n\n";
                while (!_kbhit()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                (void)_getch();
                break;
            }
            default: std::cout << "Invalid choice.\n"; pressEnterToContinue(); break;
            }
            midiIn.cancelCallback();
            midiIn.cancelUmpCallback();
        }
    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
        pressEnterToContinue();
    }
}



struct LatencyStats {
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<double> latencies;
    bool received = false;
};

void latency_direct_callback(const BYTE* data, size_t size, double timestamp, void* userData) {
    auto* stats = static_cast<LatencyStats*>(userData);
    auto receive_time = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(stats->mtx);
        stats->latencies.push_back(std::chrono::duration<double, std::micro>(receive_time.time_since_epoch()).count());
        stats->received = true;
    }
    stats->cv.notify_one();
}

void benchmarkLatency() {
    printHeader("Round-Trip Latency Benchmark");
    std::cout << "This test measures the time from a sendMessage() call to the moment the\n"
        << "data arrives in the low-latency DirectCallback. A physical loopback\n"
        << "connection (MIDI OUT -> MIDI IN) is required.\n\n";

    std::cout << "Select a MIDI Output port:\n";
    int outPort = selectPort(false);
    if (outPort == -1) { pressEnterToContinue(); return; }

    std::cout << "\nSelect a MIDI Input port:\n";
    int inPort = selectPort(true);
    if (inPort == -1) { pressEnterToContinue(); return; }

    try {
        ksmidi::MidiOut midiOut;
        ksmidi::MidiIn midiIn;
        LatencyStats stats;

        midiOut.openPort(outPort);

        midiIn.openPort(inPort);
        midiIn.setDirectCallback(latency_direct_callback, &stats);

        std::cout << "\nStarting benchmark... Running 500 iterations.\n";

        const int iterations = 500;
        BYTE msg[] = { 0x90, 60, 100 };
        std::vector<double> results_us;

        for (int i = 0; i < iterations; ++i) {
            {
                std::unique_lock<std::mutex> lock(stats.mtx);
                stats.received = false;
            }

            auto send_time = std::chrono::high_resolution_clock::now();
            midiOut.sendMessage(msg, sizeof(msg));

            {
                std::unique_lock<std::mutex> lock(stats.mtx);
                if (stats.cv.wait_for(lock, std::chrono::milliseconds(100), [&] { return stats.received; })) {
                    double send_time_us = std::chrono::duration<double, std::micro>(send_time.time_since_epoch()).count();
                    results_us.push_back(stats.latencies.back() - send_time_us);
                }
                else {
                    std::cout << "Warning: Timeout waiting for message " << i << ". Check loopback cable.\n";
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        midiIn.cancelDirectCallback();

        if (results_us.empty()) {
            std::cout << "\nNo data received. Cannot calculate statistics.\n";
        }
        else {
            double sum = std::accumulate(results_us.begin(), results_us.end(), 0.0);
            double mean = sum / results_us.size();
            double sq_sum = std::inner_product(results_us.begin(), results_us.end(), results_us.begin(), 0.0);
            double stdev = std::sqrt(sq_sum / results_us.size() - mean * mean);
            auto min = *std::min_element(results_us.begin(), results_us.end());
            auto max = *std::max_element(results_us.begin(), results_us.end());

            std::cout << "\n--- Latency Results (" << results_us.size() << " samples) ---\n";
            std::cout << std::fixed << std::setprecision(3);
            std::cout << "Average: " << mean << " us\n";
            std::cout << "Min    : " << min << " us\n";
            std::cout << "Max    : " << max << " us\n";
            std::cout << "Jitter (StdDev): " << stdev << " us\n";
        }

    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
    }
    pressEnterToContinue();
}

void benchmarkThroughput() {
    printHeader("Output Throughput Benchmark");
    std::cout << "This test sends MIDI messages as fast as possible for 5 seconds to\n"
        << "measure the maximum sustainable output rate.\n\n";

    int outPort = selectPort(false);
    if (outPort == -1) { pressEnterToContinue(); return; }

    try {
        ksmidi::MidiOut midiOut;
        midiOut.openPort(outPort);

        std::cout << "\nStarting benchmark...\n";

        BYTE msg[] = { 0xB0, 7, 0 }; 
        long long message_count = 0;
        long long byte_count = 0;

        auto start_time = std::chrono::high_resolution_clock::now();
        auto end_time = start_time + std::chrono::seconds(5);

        while (std::chrono::high_resolution_clock::now() < end_time) {
            midiOut.sendMessage(msg, sizeof(msg));
            message_count++;
            byte_count += sizeof(msg);
            msg[2]++;
            if (msg[2] > 127) msg[2] = 0;
        }

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        std::cout << "\n--- Throughput Results ---\n";
        std::cout << "Duration: " << duration / 1000.0 << " s\n";
        std::cout << "Messages Sent: " << message_count << "\n";
        std::cout << "Bytes Sent: " << byte_count << "\n";
        std::cout << "Message Rate: " << (long long)(message_count / (duration / 1000.0)) << " messages/sec\n";
        std::cout << "Data Rate: " << (byte_count / (duration / 1000.0) / 1024.0) << " KB/sec\n";

    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
    }
    pressEnterToContinue();
}

void benchmarkTimestamping() {
    printHeader("Timestamping Accuracy Test");
    int port = selectPort(true);
    if (port == -1) { pressEnterToContinue(); return; }

    std::cout << "\nSelect timestamp mode:\n"
        << "1: QPC (QueryPerformanceCounter) - Default\n"
        << "2: Driver (KSSTREAM_HEADER PresentationTime)\n"
        << "Choice: ";
    int choice;
    std::cin >> choice;

    ksmidi::MidiIn::Settings settings;
    if (choice == 2) {
        settings.timestampMode = ksmidi::MidiIn::TimestampMode::Driver;
    }
    else {
        settings.timestampMode = ksmidi::MidiIn::TimestampMode::QPC;
    }

    std::cout << "\nMonitoring port using " << (choice == 2 ? "Driver" : "QPC") << " timestamps.\n"
        << "Timestamps are relative to the first message received.\n"
        << "Press any key to stop.\n\n"
        << "KSMidi Timestamp  | Wall-Clock Timestamp\n"
        << "------------------|---------------------\n";

    try {
        ksmidi::MidiIn midiIn;
        auto info = ksmidi::Api::getPortInfoIn(port);

        std::atomic<bool> stop_flag = false;
        auto wall_clock_start = std::chrono::high_resolution_clock::now();

        auto callback = [&](const ksmidi::MidiMessage& msg) {
            auto now = std::chrono::high_resolution_clock::now();
            double wall_clock_ts = std::chrono::duration<double>(now - wall_clock_start).count();
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << std::fixed << std::setprecision(6)
                << std::setw(17) << msg.timestamp << " | "
                << std::setw(17) << wall_clock_ts << "\n";
            };

        midiIn.openPort(port, settings);
        midiIn.setCallback(callback);

        while (!_kbhit()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        (void)_getch();

    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
    }
    pressEnterToContinue();
}


void showBenchmarksMenu() {
    while (true) {
        printHeader("Performance Benchmarks");
        std::cout
            << "1: Round-Trip Latency\n"
            << "2: Output Throughput\n"
            << "3: Timestamping Accuracy\n"
            << "0: Return to Main Menu\n"
            << "Choice: ";
        int choice;
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            choice = -1;
        }

        switch (choice) {
        case 1: benchmarkLatency(); break;
        case 2: benchmarkThroughput(); break;
        case 3: benchmarkTimestamping(); break;
        case 0: return;
        default: std::cout << "Invalid choice.\n"; pressEnterToContinue(); break;
        }
    }
}


int main() {
    while (true) {
        printHeader("Main Menu");
        std::cout << "1: Detailed Port Scan\n"
            << "2: MIDI Output Tests\n"
            << "3: MIDI Input Tests\n"
            << "4: Performance Benchmarks\n"
            << "0: Exit\n"
            << "Choice: ";
        int choice;
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            choice = -1;
        }

        switch (choice) {
        case 1: testDetailedPortScan(); break;
        case 2: testMidiOut(); break;
        case 3: testMidiIn(); break;
        case 4: showBenchmarksMenu(); break;
        case 0: return 0;
        default: std::cout << "Invalid choice.\n"; pressEnterToContinue(); break;
        }
    }
}
