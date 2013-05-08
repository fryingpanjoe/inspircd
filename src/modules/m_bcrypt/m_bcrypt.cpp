/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2013 Per Lindstrand <fryingpanjoe@gmail.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/* $ModDesc: Allows for Blowfish encrypted passwords */

#include "inspircd.h"
#ifdef HAS_STDINT
#include <stdint.h>
#endif
#include "modules/hash.h"
#include "crypt_blowfish.h"

class BCryptProvider : public HashProvider
{
	const static size_t OUTPUT_SIZE = 7 + 22 + 31 + 1;

public:
	std::string sum(const std::string& data)
	{
		char output[OUTPUT_SIZE] = {0};

		// extract the setting string ($<variant>$<rounds>$<salt>)
		const std::string setting = data.substr(0, 29);

		// extract the key to hash
		const std::string key = data.substr(29);

		_crypt_blowfish_rn(key.c_str(), setting.c_str(), output, OUTPUT_SIZE);

		return std::string(output);
	}

	BCryptProvider(Module* parent) : HashProvider(parent, "hash/bcrypt", OUTPUT_SIZE, 16) {}
};

class ModuleBCrypt : public Module
{
	BCryptProvider bcrypt;

public:
	ModuleBCrypt() : bcrypt(this)
	{
		ServerInstance->Modules->AddService(bcrypt);
	}

	Version GetVersion()
	{
		return Version("Implements bcrypt hashing", VF_VENDOR);
	}
};

MODULE_INIT(ModuleBCrypt)
