/*
    KSMidi Test Suite MIDI 1.0
    -------------------------------
    Tests all functionality using loopbe virtual port
*/

#include <catch2/catch_all.hpp>
#include "KSMidi.h"
#include <chrono>
#include <thread>
#include <random>
#include <set>
#include <mutex>
#include <atomic>
#include <iostream>

using namespace ksmidi;
using namespace std::chrono_literals;

constexpr unsigned int LOOP_PORT = 0;
constexpr auto TEST_TIMEOUT = 200ms;
constexpr auto SETTLE_TIME = 50ms;

struct TestSetup {
    TestSetup() {
        try {
            auto info = Api::getPortInfoIn(LOOP_PORT);
            std::cout << "Using port " << LOOP_PORT << ": " << info.name << "\n\n";
        }
        catch (...) {
            std::cout << "Warning: Cannot access port " << LOOP_PORT << "\n\n";
        }
    }
} testSetup;

template<typename T>
std::optional<T> waitForMessage(MidiIn& in, std::chrono::milliseconds timeout = TEST_TIMEOUT) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        if (auto msg = in.pop_message()) {
            return msg;
        }
        std::this_thread::sleep_for(2ms);
    }
    return std::nullopt;
}

void waitForPortsReady() {
    std::this_thread::sleep_for(100ms);
}

TEST_CASE("Device Enumeration", "[api]") {
    SECTION("Get port counts") {
        auto inCount = Api::getPortCountIn();
        auto outCount = Api::getPortCountOut();

        REQUIRE(inCount > 0);
        REQUIRE(outCount > 0);
        INFO("Found " << inCount << " input ports and " << outCount << " output ports");
    }

    SECTION("Get port info") {
        auto info = Api::getPortInfoIn(LOOP_PORT);
        REQUIRE(!info.name.empty());
        REQUIRE(info.isAvailable);
        REQUIRE(!info.path.empty());

        REQUIRE(info.name.find("LoopBe") != std::string::npos);
    }

    SECTION("Invalid port number throws") {
        auto count = Api::getPortCountIn();
        REQUIRE_THROWS_AS(Api::getPortInfoIn(count + 100), KsMidiError);
        REQUIRE_THROWS_AS(Api::getPortInfoOut(9999), KsMidiError);
    }
}

TEST_CASE("Port Opening and Closing", "[port]") {
    SECTION("Open valid port") {
        MidiIn in;
        MidiOut out;

        REQUIRE_NOTHROW(in.openPort(LOOP_PORT));
        REQUIRE_NOTHROW(out.openPort(LOOP_PORT));

        REQUIRE(in.isPortOpen());
        REQUIRE(out.isPortOpen());

        in.closePort();
        out.closePort();

        REQUIRE(!in.isPortOpen());
        REQUIRE(!out.isPortOpen());
    }

    SECTION("Open invalid port") {
        MidiIn in;
        MidiOut out;

        REQUIRE_THROWS_AS(in.openPort(9999), KsMidiError);
        REQUIRE_THROWS_AS(out.openPort(9999), KsMidiError);
    }

    SECTION("Double open same port") {
        MidiIn in1, in2;
        in1.openPort(LOOP_PORT);

        try {
            in2.openPort(LOOP_PORT);
            REQUIRE(in1.isPortOpen());
            REQUIRE(in2.isPortOpen());
        }
        catch (const KsMidiError&) {
            REQUIRE(in1.isPortOpen());
        }
    }

    SECTION("Reopen after close") {
        MidiIn in;

        in.openPort(LOOP_PORT);
        in.closePort();
        REQUIRE_NOTHROW(in.openPort(LOOP_PORT));
        REQUIRE(in.isPortOpen());
    }
}

TEST_CASE("Basic MIDI 1.0 Messaging", "[midi1]") {
    MidiIn in;
    MidiOut out;
    in.openPort(LOOP_PORT);
    out.openPort(LOOP_PORT);
    waitForPortsReady();

    // Clear any pending messages
    while (in.pop_message().has_value());

    SECTION("Note On/Off") {
        std::vector<BYTE> noteOn = { 0x90, 60, 127 };   // Note On C4
        std::vector<BYTE> noteOff = { 0x80, 60, 64 };   // Note Off C4

        out.sendMessage(noteOn);
        auto msg1 = waitForMessage<MidiMessage>(in);
        REQUIRE(msg1.has_value());
        REQUIRE(msg1->bytes == noteOn);

        out.sendMessage(noteOff);
        auto msg2 = waitForMessage<MidiMessage>(in);
        REQUIRE(msg2.has_value());
        REQUIRE(msg2->bytes == noteOff);
    }

    SECTION("All message types") {
        // Since we are testing all types, disable all filters
        in.closePort();
        in.ignoreTypes(false, false, false); // Allow SysEx, Time, and Sense
        in.openPort(LOOP_PORT);
        waitForPortsReady();
        while (in.pop_message().has_value()); // Clear queue after reopening

        struct TestMsg {
            std::string name;
            std::vector<BYTE> data;
        };

        std::vector<TestMsg> messages = {
            {"Note On", {0x92, 64, 100}},
            {"Note Off", {0x82, 64, 0}},
            {"Poly Pressure", {0xA3, 60, 50}},
            {"Control Change", {0xB4, 7, 127}},
            {"Program Change", {0xC5, 42}},
            {"Channel Pressure", {0xD6, 100}},
            {"Pitch Bend", {0xE7, 0x00, 0x40}},
            {"System Exclusive", {0xF0, 0x7E, 0x00, 0x06, 0x01, 0xF7}},
            {"Time Code", {0xF1, 0x30}},
            {"Song Position", {0xF2, 0x00, 0x08}},
            {"Song Select", {0xF3, 0x02}},
            {"Tune Request", {0xF6}},
            {"Clock", {0xF8}},
            {"Start", {0xFA}},
            {"Continue", {0xFB}},
            {"Stop", {0xFC}},
            {"Active Sensing", {0xFE}},
            {"System Reset", {0xFF}}
        };

        for (const auto& test : messages) {
            INFO("Testing: " << test.name);
            out.sendMessage(test.data);
            auto msg = waitForMessage<MidiMessage>(in, 300ms);  // Longer timeout for system messages
            REQUIRE(msg.has_value());
            REQUIRE(msg->bytes == test.data);
        }
    }

    SECTION("Running status") {
        // Send multiple notes with running status
        out.sendMessage(std::vector<BYTE>{0x90, 60, 100});
        out.sendMessage(std::vector<BYTE>{60, 0});  // Note off using running status
        out.sendMessage(std::vector<BYTE>{62, 100}); // Another note on

        auto msg1 = waitForMessage<MidiMessage>(in);
        auto msg2 = waitForMessage<MidiMessage>(in);
        auto msg3 = waitForMessage<MidiMessage>(in);

        REQUIRE(msg1.has_value());
        REQUIRE(msg2.has_value());
        REQUIRE(msg3.has_value());

        // Parser should reconstruct full messages
        REQUIRE(msg1->bytes == std::vector<BYTE>{0x90, 60, 100});
        REQUIRE(msg2->bytes == std::vector<BYTE>{0x90, 60, 0});
        REQUIRE(msg3->bytes == std::vector<BYTE>{0x90, 62, 100});
    }
}

TEST_CASE("SysEx Handling", "[sysex]") {
    SECTION("SysEx ignored by default") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        std::vector<BYTE> sysex = { 0xF0, 0x43, 0x12, 0x00, 0x41, 0x01, 0x02, 0xF7 };
        out.sendMessage(sysex);

        auto msg = waitForMessage<MidiMessage>(in, 100ms);
        REQUIRE(!msg.has_value());  // Should be ignored
    }

    SECTION("SysEx enabled") {
        MidiIn in;
        MidiOut out;
        in.ignoreTypes(false, true, true);  // Enable sysex
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        std::vector<BYTE> sysex = { 0xF0, 0x43, 0x12, 0x00, 0x41, 0x01, 0x02, 0xF7 };
        out.sendMessage(sysex);

        auto msg = waitForMessage<MidiMessage>(in);
        REQUIRE(msg.has_value());
        REQUIRE(msg->bytes == sysex);
        REQUIRE(!msg->isSysExChunk);
    }

    SECTION("Large SysEx chunking") {
        MidiIn in;
        MidiOut out;
        MidiIn::Settings settings;
        settings.sysexChunkSize = 64;  // Small chunks
        settings.ignoreSysex = false;

        in.openPort(LOOP_PORT, settings);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        // Create large sysex
        std::vector<BYTE> largeSysex;
        largeSysex.push_back(0xF0);
        for (int i = 0; i < 200; ++i) {
            largeSysex.push_back(i & 0x7F);
        }
        largeSysex.push_back(0xF7);

        out.sendMessage(largeSysex);

        std::vector<MidiMessage> chunks;
        auto deadline = std::chrono::steady_clock::now() + 1s;

        while (std::chrono::steady_clock::now() < deadline) {
            if (auto msg = in.pop_message()) {
                chunks.push_back(*msg);
                if (!msg->isSysExChunk && msg->bytes.back() == 0xF7) {
                    break;
                }
            }
            std::this_thread::sleep_for(2ms);
        }

        REQUIRE(chunks.size() > 1);

        for (size_t i = 0; i < chunks.size() - 1; ++i) {
            REQUIRE(chunks[i].isSysExChunk);
        }
        REQUIRE(!chunks.back().isSysExChunk);  // Last has F7

        std::vector<BYTE> reconstructed;
        for (const auto& chunk : chunks) {
            reconstructed.insert(reconstructed.end(),
                chunk.bytes.begin(), chunk.bytes.end());
        }
        REQUIRE(reconstructed == largeSysex);
    }
}
//won't work in  this test
TEST_CASE("MIDI 2.0 UMP Support", "[midi2][ump]") {
    MidiIn in;
    MidiOut out;

    in.openPort(LOOP_PORT);
    out.openPort(LOOP_PORT);

    if (!in.isUmpStream() || !out.isUmpStream()) {
        WARN("Port does not support MIDI 2.0/UMP - skipping UMP tests");
        return;
    }

    SECTION("UMP Note messages") {
        auto noteOn = ump::makeNoteOn(0, 1, 60, 0x8000);
        auto noteOff = ump::makeNoteOff(0, 1, 60, 0x4000);

        out.sendMessage(noteOn);
        out.sendMessage(noteOff);

        std::this_thread::sleep_for(100ms);

        ump::UmpMessage msg;
        REQUIRE(in.try_pop_ump_message(msg));
        REQUIRE(ump::getMessageType(msg) == ump::MIDI2_CHANNEL_VOICE);
        REQUIRE(ump::getNoteNumber(msg) == 60);
        REQUIRE(ump::getMidi2Velocity(msg) == 0x8000);

        REQUIRE(in.try_pop_ump_message(msg));
        REQUIRE(ump::getMidi2Velocity(msg) == 0x4000);
    }

    SECTION("All UMP message types") {
        std::vector<ump::UmpMessage> testMessages = {
            ump::makeUtilityMessage(0, 0x20, 0x1234),  // NOOP
            ump::makeMidi1NoteOn(0, 0, 64, 100),
            ump::makeControlChange(0, 0, 7, 0xFFFFFFFF),
            ump::makeProgramChange(0, 0, 42, true, 0x3FFF),
            ump::makePitchBend(0, 0, 0x80000000)
        };

        for (const auto& msg : testMessages) {
            out.sendMessage(msg);
        }

        std::this_thread::sleep_for(200ms);

        for (size_t i = 0; i < testMessages.size(); ++i) {
            ump::UmpMessage received;
            REQUIRE(in.try_pop_ump_message(received));
            REQUIRE(received.words[0] == testMessages[i].words[0]);
            if (testMessages[i].size_in_words > 1) {
                REQUIRE(received.words[1] == testMessages[i].words[1]);
            }
        }
    }
}

TEST_CASE("Timestamp Modes", "[timestamp]") {
    std::vector<BYTE> testNote = { 0x90, 60, 100 };

    SECTION("No timestamp mode") {
        MidiIn in;
        MidiOut out;
        MidiIn::Settings settings;
        settings.timestampMode = MidiIn::TimestampMode::None;

        in.openPort(LOOP_PORT, settings);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        out.sendMessage(testNote);
        auto msg = waitForMessage<MidiMessage>(in);

        REQUIRE(msg.has_value());
        REQUIRE(msg->timestamp == 0.0);
    }

    SECTION("QPC timestamp mode") {
        MidiIn in;
        MidiOut out;
        MidiIn::Settings settings;
        settings.timestampMode = MidiIn::TimestampMode::QPC;

        in.openPort(LOOP_PORT, settings);
        out.openPort(LOOP_PORT);
        waitForPortsReady();
        std::this_thread::sleep_for(100ms);

        out.sendMessage(testNote);
        auto msg1 = waitForMessage<MidiMessage>(in);

        std::this_thread::sleep_for(50ms);
        out.sendMessage(testNote);
        auto msg2 = waitForMessage<MidiMessage>(in);

        REQUIRE(msg1.has_value());
        REQUIRE(msg2.has_value());
        REQUIRE(msg1->timestamp >= 0.0);
        REQUIRE(msg2->timestamp > msg1->timestamp);

        double delta = msg2->timestamp - msg1->timestamp;
        REQUIRE(delta > 0.04);  // At least 40ms
        REQUIRE(delta < 0.10);  // Less than 100ms
    }

    SECTION("Driver timestamp mode") {
        MidiIn in;
        MidiOut out;
        MidiIn::Settings settings;
        settings.timestampMode = MidiIn::TimestampMode::Driver;

        in.openPort(LOOP_PORT, settings);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        out.sendMessage(testNote);
        auto msg = waitForMessage<MidiMessage>(in);

        REQUIRE(msg.has_value());
        INFO("Driver timestamp: " << msg->timestamp);
    }
}

TEST_CASE("Callback Modes", "[callback]") {
    SECTION("Message callback") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        std::vector<MidiMessage> received;
        std::mutex mtx;

        in.setCallback([&](const MidiMessage& msg) {
            std::lock_guard<std::mutex> guard(mtx);
            received.push_back(msg);
            });

        std::vector<BYTE> note1 = { 0x90, 60, 100 };
        std::vector<BYTE> note2 = { 0x90, 62, 100 };

        out.sendMessage(note1);
        out.sendMessage(note2);

        std::this_thread::sleep_for(200ms);

        REQUIRE(received.size() == 2);
        REQUIRE(received[0].bytes == note1);
        REQUIRE(received[1].bytes == note2);

        in.cancelCallback();
    }

    SECTION("Direct callback") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        struct CallbackData {
            std::vector<std::vector<BYTE>> messages;
            std::vector<double> timestamps;
            std::mutex mtx;
        } data;

        in.setDirectCallback([](const BYTE* bytes, size_t size,
            double timestamp, void* userData) {
                auto* data = static_cast<CallbackData*>(userData);
                std::lock_guard<std::mutex> guard(data->mtx);
                data->messages.emplace_back(bytes, bytes + size);
                data->timestamps.push_back(timestamp);
            }, &data);

        out.sendMessage(std::vector<BYTE>{0x90, 60, 100});
        out.sendMessage(std::vector<BYTE>{0x80, 60, 0});

        std::this_thread::sleep_for(200ms);

        REQUIRE(data.messages.size() == 2);
        REQUIRE(data.messages[0] == std::vector<BYTE>{0x90, 60, 100});
        REQUIRE(data.messages[1] == std::vector<BYTE>{0x80, 60, 0});

        in.cancelDirectCallback();
    }

    SECTION("Error callback") {
        MidiIn in;
        std::vector<KsMidiError> errors;

        in.setErrorCallback([&](const KsMidiError& err) {
            errors.push_back(err);
            });

        try {
            in.openPort(9999);
        }
        catch (const KsMidiError&) {
        }

        REQUIRE(errors.empty());
    }
}

TEST_CASE("Queue Operations", "[queue]") {
    SECTION("Queue overflow handling") {
        MidiIn in;
        MidiOut out;
        MidiIn::Settings settings;
        settings.messageQueueSize = 16;

        in.openPort(LOOP_PORT, settings);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        for (int i = 0; i < 32; ++i) {
            out.sendMessage(std::vector<BYTE>{0x90, static_cast<BYTE>(60 + i), 100});
        }

        std::this_thread::sleep_for(200ms);

        int count = 0;
        while (in.pop_message().has_value()) {
            count++;
        }

        REQUIRE(count <= 16);
        INFO("Received " << count << " messages out of 32 sent");
    }

    SECTION("try_pop vs pop") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        MidiMessage msg;
        REQUIRE(!in.try_pop_message(msg));
        REQUIRE(!in.pop_message().has_value());

        out.sendMessage(std::vector<BYTE>{0x90, 60, 100});
        std::this_thread::sleep_for(100ms);

        REQUIRE(in.try_pop_message(msg));
        REQUIRE(msg.bytes == std::vector<BYTE>{0x90, 60, 100});

        REQUIRE(!in.try_pop_message(msg));
    }
}

TEST_CASE("Filtering Options", "[filter]") {
    MidiIn in;
    MidiOut out;

    SECTION("Ignore timing messages") {
        in.closePort();
        in.ignoreTypes(true, false, true);
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();
        while (in.pop_message());

        out.sendMessage(std::vector<BYTE>{0xF8});
        out.sendMessage(std::vector<BYTE>{0xFA});

        std::this_thread::sleep_for(100ms);

        int count = 0;
        while (in.pop_message().has_value()) count++;
        REQUIRE(count == 2);
    }

    SECTION("Ignore active sensing") {
        in.closePort();
        in.ignoreTypes(true, true, false);
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();
        while (in.pop_message());

        out.sendMessage(std::vector<BYTE>{0xFE});

        std::this_thread::sleep_for(100ms);

        auto msg = in.pop_message();
        REQUIRE(msg.has_value());
        REQUIRE(msg->bytes == std::vector<BYTE>{0xFE});
    }

    SECTION("Cannot change while open") {
        in.openPort(LOOP_PORT);
        REQUIRE_THROWS_AS(in.ignoreTypes(false, false, false), KsMidiError);
    }
}

TEST_CASE("Thread Safety", "[thread]") {
    SECTION("Concurrent send/receive") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        std::atomic<int> sent{ 0 };
        std::atomic<int> received{ 0 };
        std::atomic<bool> stop{ false };

        std::thread sender([&] {
            std::mt19937 rng(42);
            std::uniform_int_distribution<int> note(40, 80);
            std::uniform_int_distribution<int> vel(1, 127);

            while (!stop.load()) {
                try {
                    out.sendMessage(std::vector<BYTE>{0x90, static_cast<BYTE>(note(rng)),
                        static_cast<BYTE>(vel(rng))});
                    sent.fetch_add(1);
                    std::this_thread::sleep_for(2ms);
                }
                catch (...) {
                    break;
                }
            }
            });

        std::thread receiver([&] {
            while (!stop.load()) {
                try {
                    MidiMessage msg;
                    if (in.try_pop_message(msg)) {
                        received.fetch_add(1);
                    }
                    std::this_thread::sleep_for(1ms);
                }
                catch (...) {
                    break;
                }
            }
            });

        std::this_thread::sleep_for(200ms);
        stop = true;

        sender.join();
        receiver.join();

        std::this_thread::sleep_for(100ms);
        MidiMessage finalMsg;
        while (in.try_pop_message(finalMsg)) {
            received.fetch_add(1);
        }

        INFO("Sent: " << sent << ", Received: " << received);
        REQUIRE(received.load() > 0);
        REQUIRE(received.load() <= sent.load());
    }

    SECTION("Single reader correctness") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        while (in.pop_message().has_value());

        const int NUM_MESSAGES = 100;
        std::set<int> sent_notes;

        for (int i = 0; i < NUM_MESSAGES; ++i) {
            int note = 21 + i;
            sent_notes.insert(note);
            out.sendMessage(std::vector<BYTE>{0x90, static_cast<BYTE>(note), 100});
            std::this_thread::sleep_for(1ms);
        }

        std::set<int> received_notes;
        auto deadline = std::chrono::steady_clock::now() + 2s;

        while (received_notes.size() < NUM_MESSAGES &&
            std::chrono::steady_clock::now() < deadline) {
            if (auto msg = in.pop_message()) {
                if (msg->bytes.size() >= 2 && msg->bytes[0] == 0x90) {
                    received_notes.insert(msg->bytes[1]);
                }
            }
            std::this_thread::sleep_for(1ms);
        }

        REQUIRE(received_notes == sent_notes);
    }
}

TEST_CASE("Error Handling", "[error]") {
    SECTION("Send to closed port") {
        MidiOut out;
        REQUIRE_NOTHROW(out.sendMessage(std::vector<BYTE>{0x90, 60, 100}));  // Should no-op
    }

    SECTION("Receive from closed port") {
        MidiIn in;
        REQUIRE(!in.pop_message().has_value());
        REQUIRE(!in.isPortOpen());
    }

    SECTION("Invalid message sizes") {
        MidiOut out;
        out.openPort(LOOP_PORT);

        REQUIRE_NOTHROW(out.sendMessage(std::vector<BYTE>{}));

        std::vector<BYTE> large(65536, 0);
        REQUIRE_NOTHROW(out.sendMessage(large));
    }

    SECTION("Port unavailable") {
        MidiOut out1, out2;

        for (unsigned int i = 0; i < Api::getPortCountOut(); ++i) {
            auto info = Api::getPortInfoOut(i);
            if (!info.isAvailable) {
                REQUIRE_THROWS_AS(out1.openPort(i), KsMidiError);
                break;
            }
        }
    }
}

TEST_CASE("Memory Management", "[memory]") {
    SECTION("Move semantics") {
        MidiIn in1;
        in1.openPort(LOOP_PORT);
        REQUIRE(in1.isPortOpen());

        MidiIn in2(std::move(in1));
        REQUIRE(in2.isPortOpen());

        MidiIn in3;
        in3 = std::move(in2);
        REQUIRE(in3.isPortOpen());
    }

    SECTION("RAII cleanup") {
        {
            MidiIn in;
            MidiOut out;
            in.openPort(LOOP_PORT);
            out.openPort(LOOP_PORT);
        }

        MidiIn in;
        REQUIRE_NOTHROW(in.openPort(LOOP_PORT));
    }

    SECTION("Queue memory cleanup") {
        MidiIn in;
        MidiOut out;
        in.ignoreTypes(false, true, true);
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        for (int i = 0; i < 100; ++i) {
            std::vector<BYTE> sysex(1024);
            sysex[0] = 0xF0;
            std::fill(sysex.begin() + 1, sysex.end() - 1, 0x42);
            sysex.back() = 0xF7;
            out.sendMessage(sysex);
        }
    }
}

TEST_CASE("Performance Tests", "[!benchmark]") {
    MidiIn in;
    MidiOut out;
    in.openPort(LOOP_PORT);
    out.openPort(LOOP_PORT);
    waitForPortsReady();

    SECTION("Single note latency") {
        // Clear queue
        while (in.pop_message().has_value());

        auto start = std::chrono::high_resolution_clock::now();
        out.sendMessage(std::vector<BYTE>{0x90, 60, 100});

        while (!in.pop_message().has_value()) {
        }
        auto end = std::chrono::high_resolution_clock::now();

        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        INFO("Latency: " << latency << " microseconds");
        REQUIRE(latency < 20000); // Less than 20ms
    }

    SECTION("Throughput - 1000 messages") {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000; ++i) {
            out.sendMessage(std::vector<BYTE>{0x90, static_cast<BYTE>(i % 128), 100});
        }

        int received = 0;
        auto deadline = std::chrono::steady_clock::now() + 2s;
        while (received < 1000 && std::chrono::steady_clock::now() < deadline) {
            if (in.pop_message().has_value()) {
                received++;
            }
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        INFO("Throughput: " << (1000.0 * 1000.0 / duration) << " messages/second");
        REQUIRE(received == 1000);
    }
}

TEST_CASE("Edge Cases", "[edge]") {
    SECTION("Rapid open/close cycles") {
        MidiIn in;
        for (int i = 0; i < 10; ++i) {
            in.openPort(LOOP_PORT);
            REQUIRE(in.isPortOpen());
            in.closePort();
            REQUIRE(!in.isPortOpen());
        }
    }

    SECTION("Callback changes during operation") {
        MidiIn in;
        MidiOut out;
        in.openPort(LOOP_PORT);
        out.openPort(LOOP_PORT);
        waitForPortsReady();

        std::atomic<int> count1{ 0 }, count2{ 0 };

        in.setCallback([&](const MidiMessage&) { count1++; });
        out.sendMessage(std::vector<BYTE>{0x90, 60, 100});
        std::this_thread::sleep_for(100ms);

        in.setCallback([&](const MidiMessage&) { count2++; });
        out.sendMessage(std::vector<BYTE>{0x90, 62, 100});
        std::this_thread::sleep_for(100ms);

        REQUIRE(count1 == 1);
        REQUIRE(count2 == 1);
    }

    SECTION("All ports enumeration") {
        auto inCount = Api::getPortCountIn();
        auto outCount = Api::getPortCountOut();

        for (unsigned int i = 0; i < inCount; ++i) {
            auto info = Api::getPortInfoIn(i);
            INFO("Input port " << i << ": " << info.name);
            REQUIRE(!info.name.empty());
        }

        for (unsigned int i = 0; i < outCount; ++i) {
            auto info = Api::getPortInfoOut(i);
            INFO("Output port " << i << ": " << info.name);
            REQUIRE(!info.name.empty());
        }
    }
}

int main(int argc, char* argv[])
{
    return Catch::Session().run(argc, argv);
}
