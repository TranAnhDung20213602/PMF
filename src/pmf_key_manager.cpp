#include "pmf_key_manager.h"
#include <openssl/rand.h>

PMFKeyManager::PMFKeyManager() {
    RAND_bytes(igtk.data(), IGTK_LEN);
}

std::array<uint8_t, PMFKeyManager::IGTK_LEN>
PMFKeyManager::getIGTK() const {
    return igtk;
}
