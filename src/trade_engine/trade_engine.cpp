#include <libengine/Engine.h>
#include <boost/lockfree/policies.hpp>
#include <iostream>
#include <map>
#include <set>

class Subscription : public Connection::Subscription
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
			std::print(std::cout, "{}{}{}@{} ", username, sign, trade.m_size, trade.m_price);
		}
		std::println(std::cout, "");
	}

	void process_trade(OrderBookProcessor::Trade const& trade) override
	{
		this->m_current_block.push_back(trade);
	}
};


int main(int, char**)
{
	using namespace std::chrono_literals;
	Engine engine;
	

	auto const connection = engine.create_connection();
	connection->connect({});
	connection->subscribe_for_updates(std::make_unique<Subscription>());
	connection->place_buy_order("T1", 5, 30);
	connection->place_sell_order("T2", 5, 70);
	connection->place_buy_order("T3", 1, 40);
	connection->place_sell_order("T4", 2, 60);

	connection->place_sell_order("T5", 3, 70);
	connection->place_sell_order("T6", 20, 80);
	connection->place_sell_order("T7", 1, 50);
	connection->place_sell_order("T2", 5, 70);

	connection->place_buy_order("T1", 1, 50);
	connection->place_buy_order("T1", 3, 60);
	connection->place_sell_order("T7", 2, 50);
	connection->place_buy_order("T8", 10, 90);

	engine.start();
	engine.finalize();
	engine.stop();

	return 0;
}