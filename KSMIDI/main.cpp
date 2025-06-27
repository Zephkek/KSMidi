/*
    KSMidi Test App – main.cpp
    ---------------------------
    Author: Mohamed Maatallah
    Date: June 27, 2025

    This is the official command-line tester for the KSMidi library.
    It gives you a hands-on way to explore everything KSMidi offers:
    real-time MIDI input, ultra-low-latency output, port scanning, SysEx tests,
    and callback-based message handling — all using pure Windows Kernel Streaming (KS).

    If you're building something that demands tight MIDI performance on Windows,
    this app will show you what KSMidi is capable of currently.
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
        << "  KSMidi Test: " << title << "\n"
        << "========================================================\n\n";
}

void printMessage(const ksmidi::MidiMessage& msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << std::fixed << std::setprecision(4) << msg.timestamp << " | "
        << msg.source << " | ";

    if (msg.bytes.empty()) {
        std::cout << "Empty Message\n";
        return;
    }

    const unsigned char status = msg.bytes[0];
    const unsigned char high_nibble = status & 0xF0;
    const unsigned char channel = (status & 0x0F) + 1;

    switch (high_nibble) {
    case 0x80: std::cout << "Note Off (Ch " << static_cast<int>(channel) << ", Key " << static_cast<int>(msg.bytes[1]) << ", Vel " << static_cast<int>(msg.bytes[2]) << ")\n"; break;
    case 0x90: std::cout << (msg.bytes[2] > 0 ? "Note On  " : "Note Off ") << "(Ch " << static_cast<int>(channel) << ", Key " << static_cast<int>(msg.bytes[1]) << ", Vel " << static_cast<int>(msg.bytes[2]) << ")\n"; break;
    case 0xA0: std::cout << "Aftertouch (Ch " << static_cast<int>(channel) << ", Key " << static_cast<int>(msg.bytes[1]) << ", Pressure " << static_cast<int>(msg.bytes[2]) << ")\n"; break;
    case 0xB0: std::cout << "CC       (Ch " << static_cast<int>(channel) << ", Ctl " << static_cast<int>(msg.bytes[1]) << ", Val " << static_cast<int>(msg.bytes[2]) << ")\n"; break;
    case 0xC0: std::cout << "Program Change (Ch " << static_cast<int>(channel) << ", Pgm " << static_cast<int>(msg.bytes[1]) << ")\n"; break;
    case 0xD0: std::cout << "Channel Pressure (Ch " << static_cast<int>(channel) << ", Pressure " << static_cast<int>(msg.bytes[1]) << ")\n"; break;
    case 0xE0: std::cout << "Pitch Bend (Ch " << static_cast<int>(channel) << ", Val " << (static_cast<int>(msg.bytes[2]) << 7 | msg.bytes[1]) << ")\n"; break;
    case 0xF0:
        if (msg.isSysExChunk) std::cout << "SysEx Chunk ("; else std::cout << "SysEx (";
        std::cout << msg.bytes.size() << " bytes)\n";
        break;
    default: std::cout << "System Message (0x" << std::hex << (int)status << std::dec << ")\n"; break;
    }
}

void printError(const ksmidi::KsMidiError& err) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cerr << "\n\n--- KSMIDI RUNTIME ERROR ---\n" << err.what() << "\n----------------------------\n\n";
}

void listPorts() {
    printHeader("List MIDI Ports");
    try {
        std::cout << "[ MIDI Input Ports ]\n";
        unsigned int inPorts = ksmidi::Api::getPortCountIn();
        if (inPorts == 0) {
            std::cout << "  No input ports found.\n";
        }
        else {
            for (unsigned int i = 0; i < inPorts; ++i) {
                auto info = ksmidi::Api::getPortInfoIn(i);
                std::cout << "  " << i << ": " << info.name << (info.isAvailable ? "" : " [UNAVAILABLE/IN USE]") << '\n';
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
                std::cout << "  " << i << ": " << info.name << (info.isAvailable ? "" : " [UNAVAILABLE/IN USE]") << '\n';
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
    unsigned int portCount = ksmidi::Api::getPortCountOut();
    if (portCount == 0) {
        std::cout << "No MIDI output ports found.\n";
        pressEnterToContinue();
        return;
    }

    std::cout << "Available output ports:\n";
    for (unsigned int i = 0; i < portCount; ++i) {
        auto info = ksmidi::Api::getPortInfoOut(i);
        std::cout << "  " << i << ": " << info.name << (info.isAvailable ? "" : " [UNAVAILABLE/IN USE]") << '\n';
    }

    std::cout << "\nChoose a port number: ";
    unsigned int port;
    std::cin >> port;
    if (std::cin.fail() || port >= portCount) {
        std::cout << "Invalid selection.\n";
        pressEnterToContinue();
        return;
    }

    try {
        ksmidi::MidiOut midiOut;
        midiOut.openPort(port);
        std::cout << "Port opened successfully.\n";

        while (true) {
            printHeader("MIDI Output Test Menu");
            std::cout << "Port '" << ksmidi::Api::getPortInfoOut(port).name << "' is open.\n\n"
                << "1: Send Note On/Off (Middle C)\n"
                << "2: Send CC #7 (Volume) Sweep\n"
                << "3: Send a large SysEx message\n"
                << "0: Close port and return to main menu\n"
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
                std::cout << "\nSending CC#7 sweep from 0 to 127 and back on Ch 1...\n";
                BYTE msg[] = { 0xB0, 7, 0 }; // CC, Controller 7, Value
                for (int i = 0; i <= 127; ++i) {
                    msg[2] = i;
                    midiOut.sendMessage(msg, sizeof(msg));
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                for (int i = 127; i >= 0; --i) {
                    msg[2] = i;
                    midiOut.sendMessage(msg, sizeof(msg));
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                std::cout << "Sweep complete.\n";
                break;
            }
            case 3: {
                std::cout << "\nSending a 300-byte SysEx message...\n";
                std::vector<BYTE> sysex;
                sysex.push_back(0xF0); // Start
                sysex.push_back(0x7F); // Universal Non-Realtime
                sysex.push_back(0x7F); // ID of target device
                sysex.push_back(0x04); // Sub-ID #1 = Device Control
                sysex.push_back(0x01); // Sub-ID #2 = Master Volume
                for (int i = 0; i < 294; ++i) sysex.push_back(i % 128); // Dummy data
                sysex.push_back(0xF7); // End
                midiOut.sendMessage(sysex);
                std::cout << "SysEx sent.\n";
                break;
            }
            default: std::cout << "Invalid choice.\n"; break;
            }
            pressEnterToContinue();
        }

    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
        pressEnterToContinue();
    }
}

void testMidiIn() {
    printHeader("MIDI Input Test");
    unsigned int portCount = ksmidi::Api::getPortCountIn();
    if (portCount == 0) {
        std::cout << "No MIDI input ports found.\n";
        pressEnterToContinue();
        return;
    }

    std::cout << "Available input ports:\n";
    for (unsigned int i = 0; i < portCount; ++i) {
        auto info = ksmidi::Api::getPortInfoIn(i);
        std::cout << "  " << i << ": " << info.name << (info.isAvailable ? "" : " [UNAVAILABLE/IN USE]") << '\n';
    }

    std::cout << "\nChoose a port number: ";
    unsigned int port;
    std::cin >> port;
    if (std::cin.fail() || port >= portCount) {
        std::cout << "Invalid selection.\n";
        pressEnterToContinue();
        return;
    }

    try {
        ksmidi::MidiIn midiIn;
        ksmidi::MidiIn::Settings settings;

        std::cout << "Use default settings? (y/n): ";
        char use_defaults;
        std::cin >> use_defaults;
        if (use_defaults != 'y' && use_defaults != 'Y') {
            std::cout << "Enter buffer size (default 1024): ";
            std::cin >> settings.bufferSize;
            std::cout << "Enter buffer count (default 4, min 2): ";
            std::cin >> settings.bufferCount;
            std::cout << "Enter Sysex chunk size for callbacks (0=no chunking, default 1024): ";
            std::cin >> settings.sysexChunkSize;
        }

        midiIn.openPort(port, settings);
        midiIn.setErrorCallback(&printError);

        while (true) {
            printHeader("MIDI Input Test Menu");
            std::cout << "Port '" << ksmidi::Api::getPortInfoIn(port).name << "' is open.\n\n"
                << "1: Monitor in real-time (Callback API)\n"
                << "2: Monitor in real-time (Manual Polling API)\n"
                << "3: Test error handling (unplug device during monitor)\n"
                << "0: Close port and return to main menu\n"
                << "Choice: ";
            int choice;
            std::cin >> choice;
            if (std::cin.fail()) { choice = -1; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }

            if (choice == 0) break;

            switch (choice) {
            case 1: { 
                printHeader("Callback Monitoring");
                std::cout << "Press 's' to toggle SysEx, 't' for Time, 'n' for Sense.\n"
                    << "Press any other key to stop.\n\n";
                midiIn.setCallback(&printMessage);

                bool s = false, t = false, n = false;
                midiIn.ignoreTypes(s, t, n);
                std::cout << "Current filters: SysEx=" << s << " Time=" << t << " Sense=" << n << "\n";

                while (true) {
                    if (_kbhit()) {
                        char c = _getch();
                        if (c == 's' || c == 't' || c == 'n') {
                            if (c == 's') s = !s;
                            if (c == 't') t = !t;
                            if (c == 'n') n = !n;
                            midiIn.ignoreTypes(s, t, n);
                            {
                                std::lock_guard<std::mutex> lock(cout_mutex);
                                std::cout << "\nFilters updated: SysEx=" << s << " Time=" << t << " Sense=" << n << "\n";
                            }
                        }
                        else {
                            break; 
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                midiIn.cancelCallback();
                break;
            }
            case 2: {
                printHeader("Manual Polling Monitoring");
                std::cout << "Press any key to stop.\n\n";
                while (!_kbhit()) {
                    ksmidi::MidiMessage msg;
                    while (midiIn.try_pop_message(msg)) printMessage(msg);

                    ksmidi::KsMidiError err;
                    while (midiIn.try_pop_error(err)) printError(err);

                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                _getch(); 
                break;
            }
            case 3: { 
                printHeader("Error Handling Test");
                std::cout << "Listening for messages. Please unplug the MIDI device now to trigger an error...\n"
                    << "Press any key to stop.\n\n";
                midiIn.setCallback(&printMessage);
                while (!_kbhit()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                _getch();
                midiIn.cancelCallback();
                break;
            }
            default: std::cout << "Invalid choice.\n"; pressEnterToContinue(); break;
            }
        }
    }
    catch (const ksmidi::KsMidiError& e) {
        printError(e);
        pressEnterToContinue();
    }
}

int main() {
    while (true) {
        printHeader("Main Menu");
        std::cout << "1: List MIDI Ports\n"
            << "2: Test MIDI Output\n"
            << "3: Test MIDI Input\n"
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
        case 1: listPorts(); break;
        case 2: testMidiOut(); break;
        case 3: testMidiIn(); break;
        case 0: return 0;
        default: std::cout << "Invalid choice.\n"; pressEnterToContinue(); break;
        }
    }
}
