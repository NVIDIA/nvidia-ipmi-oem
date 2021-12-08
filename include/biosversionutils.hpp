/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#pragma once

#include <cstdint>
#include <string>
#include <fstream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>

namespace ipmi
{
namespace nvidia
{

/* information that is stored in a bios slot */
class BiosSlotInformation {
    public:
        uint8_t majorVersion;
        uint8_t minorVersion;
        std::string date; /* date of last update */
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(BiosSlotInformation, majorVersion, minorVersion, date)
};

/* storage for bios information, loads/saves to json, singleton */
class BiosVersionInformation {
    private:
        static constexpr auto storageFilePath = "/var/ipmi-bios-info.json";
        static constexpr auto nSlots = 2;
        static constexpr auto nConfigFlags = 2;
        std::array<BiosSlotInformation, nSlots> slotInfo;
        uint8_t lastBootSlot;
        std::array<bool, nConfigFlags> configFlags;


        void loadInfoFromFile(void) {
            std::ifstream i(storageFilePath);
            if (i.is_open()) {
                try {
                    nlohmann::json j;
                    i >> j;
                    j.at("slotInfo").get_to(slotInfo);
                    j.at("lastBootSlot").get_to(lastBootSlot);
                    j.at("configFlags").get_to(configFlags);
                }
                catch (nlohmann::json::out_of_range& e)
                {
                }
            }
        }

        void saveInfoToFile(void) {
            nlohmann::json j;(slotInfo);
            j["slotInfo"] = slotInfo;
            j["lastBootSlot"] = lastBootSlot;
            j["configFlags"] = configFlags;
            std::ofstream o(storageFilePath);
            o << j;
        }
        BiosVersionInformation() {
            for (auto &f : configFlags) {
                f = true;
            }
            /* load from file */
            loadInfoFromFile();
        }
    public:
        BiosVersionInformation(BiosVersionInformation const &) = delete;
        BiosVersionInformation &operator=(BiosVersionInformation const &) = delete;

        static BiosVersionInformation &get() {
            static BiosVersionInformation bvi;
            return bvi;
        }

        /* will update version and last boot slot */
        void updateBiosSlot(uint8_t slot, uint8_t majorVersion, uint8_t minorVersion) {
            if (slot >= nSlots) {
                return;
            }
            bool save = false;
            if (slot != lastBootSlot) {
                lastBootSlot = slot;
                save = true;
            }
            if ((slotInfo[slot].majorVersion != majorVersion)||(slotInfo[slot].minorVersion != minorVersion)) {
                slotInfo[slot].majorVersion = majorVersion;
                slotInfo[slot].minorVersion = minorVersion;
                slotInfo[slot].date = boost::posix_time::to_iso_string(boost::posix_time::second_clock::universal_time());
                save = true;
            }
            if (save) {
                saveInfoToFile();
            }
        }

        bool getBiosSlotInformation(uint8_t slot, uint8_t &major, uint8_t &minor) {
            if (slot >= nSlots) {
                return false;
            }
            if (slotInfo[slot].date.length() == 0) {
                /* date isn't filled in, slot info is invalid */
                return false;
            }
            major = slotInfo[slot].majorVersion;
            minor = slotInfo[slot].minorVersion;
            return true;
        }

        uint8_t getLastBootSlot(void) {
            return lastBootSlot;
        }

        bool getConfigFlag(uint8_t offset) {
            if (offset < nConfigFlags) {
                return configFlags[offset];
            }
            return false;
        }

        void setConfigFlag(uint8_t offset, bool value) {
            if ((offset < nConfigFlags)&&(value != configFlags[offset])) {
                configFlags[offset] = value;
                saveInfoToFile();
            }
        }
};

} // namespace nvidia
} // namespace ipmi