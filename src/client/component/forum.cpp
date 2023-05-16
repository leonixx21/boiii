#include <std_include.hpp>
#include "loader/component_loader.hpp"
#include "forum.hpp"

#include <utils/nt.hpp>
#include <utils/io.hpp>
#include <utils/http.hpp>
#include <utils/byte_buffer.hpp>
#include <utils/concurrency.hpp>
#include <utils/cryptography.hpp>

#include "auth.hpp"

#include "game/game.hpp"

namespace forum
{
	namespace
	{
		const auto SERVER = "http://localhost:3000"s;
		utils::concurrency::container<std::optional<user_status>> g_own_status{};

		void open_url(const std::string& url)
		{
			ShellExecuteA(nullptr, "open", url.data(), nullptr, nullptr, SW_SHOWNORMAL);
		}

		utils::cryptography::ecc::key& get_server_key()
		{
			static auto key = []
			{
				constexpr uint8_t server_key[] = //
				{
					0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
					0x81, 0x04, 0x00, 0x0A, 0x03, 0x42, 0x00, 0x04, 0xDA, 0x46, 0x22, 0x73, 0x8F, 0x07, 0x8B, 0xB4,
					0xA0, 0x2A, 0x2E, 0x1F, 0x7E, 0xF2, 0x89, 0x0C, 0x50, 0x68, 0x0C, 0x2B, 0xE3, 0x50, 0x82, 0x7E,
					0xC1, 0xBF, 0x60, 0x31, 0xC6, 0xAB, 0x6D, 0x1C, 0x14, 0x4A, 0x7B, 0x6C, 0x14, 0xC4, 0xFE, 0xE7,
					0x78, 0x12, 0x1B, 0x74, 0xC3, 0xC9, 0x88, 0x11, 0x5F, 0xD7, 0x3D, 0xD3, 0x0C, 0x13, 0x83, 0x42,
					0x5D, 0x67, 0xE5, 0x58, 0x41, 0x7F, 0xF2, 0x66,
				};

				utils::cryptography::ecc::key k{};
				k.set_openssl(std::string(reinterpret_cast<const char*>(server_key), sizeof(server_key)));

				return k;
			}();
			return key;
		}

		std::filesystem::path get_certificate_path()
		{
			return game::get_appdata_path() / "user/user.cert";
		}

		std::optional<std::string> get_certificate_data()
		{
			std::string data{};
			if (!utils::io::read_file(get_certificate_path(), &data))
			{
				return {};
			}

			return {std::move(data)};
		}

		constexpr uint32_t CERTIFICATE_VERSION = 1;

		struct certificate_data
		{
			user_id_type user_id{};
			std::string public_key{};
		};

		certificate_data parse_and_validate_certificate(std::string data)
		{
			utils::byte_buffer buffer(std::move(data));

			certificate_data certificate{};

			if (buffer.read<uint32_t>() != CERTIFICATE_VERSION)
			{
				throw std::runtime_error("Bad certificate version");
			}

			certificate.user_id = buffer.read<user_id_type>();
			certificate.public_key = buffer.read_string();

			const auto message = buffer.get_buffer().substr(0, buffer.get_offset());
			const auto signature = buffer.read_string();

			if (buffer.get_remaining_size() > 0)
			{
				throw std::runtime_error("Trailing data");
			}

			if (!utils::cryptography::ecc::verify_message(get_server_key(), message, signature))
			{
				throw std::runtime_error("Bad signature");
			}

			return certificate;
		}

		certificate_data parse_and_validate_own_certificate(std::string data)
		{
			auto certificate = parse_and_validate_certificate(std::move(data));
			if (certificate.public_key != auth::get_key().serialize(PK_PUBLIC))
			{
				return {};
			}

			return certificate;
		}

		void validate_and_store_own_certificate(const std::string& data)
		{
			(void)parse_and_validate_own_certificate(data);
			utils::io::write_file(get_certificate_path(), data);

			g_own_status.access([](std::optional<user_status>& status)
			{
				status = {};
			});
		}

		certificate_data get_own_certificate_data()
		{
			const auto data = get_certificate_data();
			if (!data)
			{
				throw std::runtime_error("No certificate");
			}

			return parse_and_validate_own_certificate(*data);
		}

		user_status resolve_own_status()
		{
			try
			{
				return get_status_for_user(get_own_certificate_data().user_id);
			}
			catch (...)
			{
				return user_status::REGULAR;
			}
		}

		bool trigger_login()
		{
			if (is_authenticated())
			{
				return true;
			}

			std::string id{};

			try
			{
				const auto result = utils::http::post_data(SERVER + "/req", auth::get_key().serialize(PK_PUBLIC), {
					                                           {
						                                           "Content-Type", "application/octet-stream",
					                                           },
				                                           });
				if (!result)
				{
					return false;
				}

				id = *result;
				open_url(SERVER + "/auth?id=" + id);
			}
			catch (...)
			{
				return false;
			}

			for (size_t i = 0; i < 60; ++i)
			{
				try
				{
					auto result = utils::http::get_data(SERVER + "/data?id=" + id);
					if (result)
					{
						validate_and_store_own_certificate(*result);
						return true;
					}
				}
				catch (...)
				{
				}

				std::this_thread::sleep_for(1s);
			}

			return false;
		}
	}

	void logout()
	{
		try
		{
			utils::io::remove_file(get_certificate_path());
		}
		catch (...)
		{
		}

		g_own_status.access([](std::optional<user_status>& status)
		{
			status = {};
		});
	}

	void perform_login(std::function<void(bool)> callback)
	{
		std::thread([c = std::move(callback)]
		{
			const auto result = trigger_login();
			if (c)
			{
				c(result);
			}
		}).detach();
	}

	bool is_authenticated()
	{
		try
		{
			(void)get_own_certificate_data();
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	user_status get_user_status()
	{
		return g_own_status.access<user_status>([](std::optional<user_status>& status)
		{
			if (status)
			{
				return *status;
			}

			const auto new_status = resolve_own_status();
			status = new_status;

			return new_status;
		});
	}

	user_status get_status_for_user(const user_id_type user_id)
	{
		try
		{
			const auto result = utils::http::get_data(SERVER + "/user?id=" + std::to_string(user_id));
			if (result)
			{
				return static_cast<user_status>(atoi(result->data()));
			}
		}
		catch (...)
		{
		}

		return user_status::REGULAR;
	}

	class component final : public generic_component
	{
	};
}

REGISTER_COMPONENT(forum::component)
