#pragma once
#include <array>
#include <cstdint>

class PMFKeyManager {
public:
    static constexpr size_t IGTK_LEN = 16;

    PMFKeyManager();
    std::array<uint8_t, IGTK_LEN> getIGTK() const;

private:
    std::array<uint8_t, IGTK_LEN> igtk;
};
