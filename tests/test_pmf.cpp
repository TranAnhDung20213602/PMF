#include <iostream>
#include <cassert>
#include <vector>

#include "pmf_key_manager.h"
#include "pmf_crypto.h"
#include "pmf_validator.h"
#include "pmf_frame.h"

// Helper: tạo MIC cho frame
void generateMIC(PMFFrame& frame, const std::vector<uint8_t>& igtk) {
    std::vector<uint8_t> data;

    // PN (64-bit, big-endian)
    for (int i = 7; i >= 0; --i) {
        data.push_back((frame.packet_number >> (i * 8)) & 0xFF);
    }

    // Payload
    data.insert(data.end(),
                frame.payload.begin(),
                frame.payload.end());

    frame.mic = PMFCrypto::computeCMAC(igtk, data);
}

int main() {
    std::cout << "[TEST] PMF Validator with Anti-Replay Counter\n";

    // 1. Khởi tạo khóa IGTK
    PMFKeyManager keyManager;
    auto igtk_array = keyManager.getIGTK();
    std::vector<uint8_t> igtk(igtk_array.begin(), igtk_array.end());

    PMFValidator validator;

    // ===============================
    // Test 1: Frame hợp lệ (PN = 1)
    // ===============================
    PMFFrame frame1;
    frame1.frame_control = 0xC0;   // Deauthentication
    frame1.packet_number = 1;
    frame1.payload = {0xDE, 0xAD, 0xBE, 0xEF};

    generateMIC(frame1, igtk);

    bool result1 = validator.validateFrame(frame1, igtk);
    assert(result1 == true);
    std::cout << "[PASS] Valid frame accepted (PN = 1)\n";

    // ===============================
    // Test 2: Replay attack (PN = 1)
    // ===============================
    bool result2 = validator.validateFrame(frame1, igtk);
    assert(result2 == false);
    std::cout << "[PASS] Replay frame rejected (PN = 1 reused)\n";

    // ===============================
    // Test 3: Frame mới nhưng MIC sai (PN = 2)
    // ===============================
    PMFFrame frame2;
    frame2.frame_control = 0xC0;
    frame2.packet_number = 2;
    frame2.payload = {0xBA, 0xAD, 0xF0, 0x0D};

    // MIC giả (sai)
    frame2.mic = {0x00, 0x01, 0x02};

    bool result3 = validator.validateFrame(frame2, igtk);
    assert(result3 == false);
    std::cout << "[PASS] Frame with invalid MIC rejected (PN = 2)\n";

    // ===============================
    // Test 4: Frame hợp lệ tiếp theo (PN = 3)
    // ===============================
    PMFFrame frame3;
    frame3.frame_control = 0xC0;
    frame3.packet_number = 3;
    frame3.payload = {0xCA, 0xFE};

    generateMIC(frame3, igtk);

    bool result4 = validator.validateFrame(frame3, igtk);
    assert(result4 == true);
    std::cout << "[PASS] New valid frame accepted (PN = 3)\n";

    std::cout << "\n[ALL TESTS PASSED]\n";
    return 0;
}
