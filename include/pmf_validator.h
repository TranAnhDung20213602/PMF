#pragma once
#include "pmf_frame.h"
#include <vector>
#include <cstdint>

class PMFValidator {
public:
    PMFValidator();

    // Xác thực frame PMF (MIC + anti-replay)
    bool validateFrame(
        const PMFFrame& frame,
        const std::vector<uint8_t>& igtk
    );

    // Reset trạng thái (ví dụ: kết nối mới)
    void reset();

private:
    uint64_t last_packet_number;

    bool checkReplay(uint64_t pn);
    bool validateMIC(
        const PMFFrame& frame,
        const std::vector<uint8_t>& igtk
    );
};
