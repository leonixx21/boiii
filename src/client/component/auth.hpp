#pragma once

#include <utils/cryptography.hpp>

namespace auth
{
	uint64_t get_guid();
	uint64_t get_guid(size_t client_num);
	void clear_stored_guids();

	utils::cryptography::ecc::key& get_key();
}
