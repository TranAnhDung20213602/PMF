#pragma once
#include <vector>
#include <cstdint>

struct PMFFrame {
    uint16_t frame_control;          
    uint64_t packet_number;        
    std::vector<uint8_t> payload;
    std::vector<uint8_t> mic;        
};
