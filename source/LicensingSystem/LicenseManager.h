//
// Created by Vlad on 12.09.2024.
//

#pragma once
#include <string>
#include <string_view>


namespace open_loader
{

    class LicenseManager
    {
    public:
        explicit LicenseManager(const std::string_view& secretKey);

        [[nodiscard]]
        [[clang::noinline]]
        std::string GenerateLicenseKey() const;

        [[nodiscard]]
        [[clang::noinline]]
        bool IsLicenseKeyValid(const std::string_view& key) const;

        [[nodiscard]]
        [[clang::noinline]]
        bool IsLicenseKeyValidFromFile(const std::string_view& pathToFile) const;
    private:

        [[nodiscard]]
        [[clang::noinline]]
        static std::string GenerateBaseKey() ;

        [[nodiscard]]
        [[clang::noinline]]
        std::string GenerateHmac(const std::string_view& baseKey) const;
        const std::string m_secretKey;
    };

} // open_loader