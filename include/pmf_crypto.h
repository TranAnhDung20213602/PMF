#pragma once
#include <vector>
#include <cstdint>

class PMFCrypto {
public:
    static std::vector<uint8_t> computeCMAC(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );
};

