#include "pmf_crypto.h"
#include <openssl/cmac.h>

std::vector<uint8_t> PMFCrypto::computeCMAC(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
    CMAC_CTX* ctx = CMAC_CTX_new();
    std::vector<uint8_t> mac(16);
    size_t mac_len;

    CMAC_Init(ctx, key.data(), key.size(), EVP_aes_128_cbc(), nullptr);
    CMAC_Update(ctx, data.data(), data.size());
    CMAC_Final(ctx, mac.data(), &mac_len);

    CMAC_CTX_free(ctx);
    mac.resize(mac_len);
    return mac;
}
