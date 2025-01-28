#include <iostream>
#include <set>

#include <libengine/Engine.h>


class Subscription final : public Connection::Subscription
{
	std::vector< OrderBookProcessor::Trade> m_current_block;

	void process_block_start() override
	{
		this->m_current_block.clear();
	}

	void process_block_end() override
	{
		auto comp = [](OrderBookProcessor::Trade const& lhs, OrderBookProcessor::Trade const& rhs)
			{
				std::string_view const left_user = lhs.m_user_info.get_username();
				std::string_view const right_user = rhs.m_user_info.get_username();
				char const left_sign = lhs.m_trade_type == OrderBookProcessor::Trade::trade_type_t::BUY ? '+' : '-';
				char const right_sign = rhs.m_trade_type == OrderBookProcessor::Trade::trade_type_t::BUY ? '+' : '-';
				auto const username_comp_res = left_user.compare(right_user);

				if (username_comp_res != 0)
					return username_comp_res < 0;
				if (left_sign != right_sign) 
					return left_sign < right_sign;
				if (lhs.m_price != rhs.m_price) 
					return lhs.m_price < rhs.m_price;

				return false;
			};

		std::set<OrderBookProcessor::Trade, decltype(comp)> trades_sorted;
		for (auto const& trade : m_current_block)
		{
			auto [it, res] = trades_sorted.emplace(trade);
			if (false == res)
				it->m_size += trade.m_size;
		}

		for(auto const& trade: trades_sorted)
		{
			std::string_view const username = trade.m_user_info.get_username();
			char const sign = trade.m_trade_type == OrderBookProcessor::Trade::trade_type_t::BUY ? '+' : '-';
			std::cout << username << sign << trade.m_size << '@' << trade.m_price << ' ';
		}
		std::cout << std::endl;
	}

	void process_trade(OrderBookProcessor::Trade const& trade) override
	{
		this->m_current_block.push_back(trade);
	}
};


int main([[maybe_unused]] int args, [[maybe_unused]] char** argv)
{
	try
	{
		Engine engine;
		engine.start();

		auto const connection = engine.create_connection();
		connection->connect({});
		connection->subscribe_for_updates(std::make_unique<Subscription>());

		std::string username;
		char sign;
		int size;
		int price;

		while (std::cin >> username)
		{
			std::cin >> sign;
			std::cin >> size;
			std::cin >> price;

			if (sign == 'B')
				connection->place_buy_order(username, size, price);
			else
				connection->place_sell_order(username, size, price);
		}

		engine.finalize();
		engine.stop();
	}
	catch (std::exception const& e)
	{
		std::cerr << "Exception thrown: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}