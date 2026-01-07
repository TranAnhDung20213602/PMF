#include "pmf_validator.h"
#include "pmf_crypto.h"

PMFValidator::PMFValidator()
    : last_packet_number(0) {}

void PMFValidator::reset() {
    last_packet_number = 0;
}

bool PMFValidator::checkReplay(uint64_t pn) {
    // PN phải tăng dần
    if (pn <= last_packet_number) {
        return false;
    }

    last_packet_number = pn;
    return true;
}

bool PMFValidator::validateMIC(
    const PMFFrame& frame,
    const std::vector<uint8_t>& igtk
) {
    // Dữ liệu tính MIC = PN || payload
    std::vector<uint8_t> data;

    for (int i = 7; i >= 0; --i) {
        data.push_back((frame.packet_number >> (i * 8)) & 0xFF);
    }

    data.insert(data.end(),
                frame.payload.begin(),
                frame.payload.end());

    auto computed =
        PMFCrypto::computeCMAC(igtk, data);

    return computed == frame.mic;
}

bool PMFValidator::validateFrame(
    const PMFFrame& frame,
    const std::vector<uint8_t>& igtk
) {
    // 1. Kiểm tra replay
    if (!checkReplay(frame.packet_number)) {
        return false;
    }

    // 2. Kiểm tra MIC
    if (!validateMIC(frame, igtk)) {
        return false;
    }

    return true;
}
