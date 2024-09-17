//
// Created by Vlad on 12.09.2024.
//

#include "LicenseManager.h"
#include <random>
#include <sstream>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <iomanip>
#include <fstream>
#include <CodeVirtualizer/VirtualizerSDK.h>

namespace open_loader
{
    LicenseManager::LicenseManager(const std::string_view &secretKey) : m_secretKey(secretKey)
    {

    }

    std::string LicenseManager::GenerateLicenseKey() const
    {
        //VIRTUALIZER_SHARK_BLACK_START;

        std::string baseKey = GenerateBaseKey();
        std::string hmac = GenerateHmac(baseKey);

        //VIRTUALIZER_SHARK_BLACK_END;
        return baseKey + "-" + hmac.substr(0, 8);
    }

    std::string LicenseManager::GenerateBaseKey()
    {
        VIRTUALIZER_MUTATE_ONLY_START

        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 9);

        std::ostringstream keyStream;
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                keyStream << dis(gen);

            if (i != 3)
                keyStream << "-";
        }
        VIRTUALIZER_MUTATE_ONLY_END
        return keyStream.str();
    }

    std::string LicenseManager::GenerateHmac(const std::string_view &baseKey) const
    {
        VIRTUALIZER_SHARK_BLACK_START;

        unsigned char* digest;
        digest = HMAC(EVP_sha256(), m_secretKey.c_str(), m_secretKey.length(),
                      reinterpret_cast<const unsigned char*>(baseKey.data()), baseKey.length(), nullptr, nullptr);

        std::ostringstream hmacStream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            hmacStream << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

        VIRTUALIZER_SHARK_BLACK_END;
        return hmacStream.str();
    }

    bool LicenseManager::IsLicenseKeyValid(const std::string_view &key) const
    {
        VIRTUALIZER_SHARK_BLACK_START;

        const auto baseKey = key.substr(0, 19);

        if (baseKey.empty())
            return false;

        const auto providedHMAC = key.substr(20, 8);

        if (providedHMAC.empty())
            return false;

        const auto isValid = providedHMAC == GenerateHmac(baseKey).substr(0, 8);

        VIRTUALIZER_SHARK_BLACK_END;
        return isValid;

    }

    bool LicenseManager::IsLicenseKeyValidFromFile(const std::string_view &pathToFile) const
    {
        VIRTUALIZER_SHARK_BLACK_START
        auto file = std::ifstream(pathToFile.data());

        if (!file.is_open())
            return false;

        std::string key;

        std::getline(file, key);

        const auto result = IsLicenseKeyValid(key);
        VIRTUALIZER_SHARK_BLACK_END
        return result;
    }
} // open_loader