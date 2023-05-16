#pragma once

namespace forum
{
	enum class user_status
	{
		REGULAR = 0,
		STAFF = 999,
		SPONSOR = 1,
		VIP_SPONSOR = 2,
	};

	using user_id_type = uint32_t;

	void logout();
	void perform_login(std::function<void(bool)> callback = {});

	bool is_authenticated();

	user_status get_user_status();
	user_status get_status_for_user(user_id_type user_id);
}
