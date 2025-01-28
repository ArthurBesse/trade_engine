#ifndef LIBENGINE_INVALID_API_USAGE_TESTS_H
#define LIBENGINE_INVALID_API_USAGE_TESTS_H
#include <gtest/gtest.h>
#include <libengine/Engine.h>

namespace invalid_api_usage_tests
{
	struct Subscription final : public Connection::Subscription
	{
		std::vector< OrderBookProcessor::Trade> m_current_block;
		std::vector<std::vector<OrderBookProcessor::Trade>>* m_blocks;
		Subscription(std::vector<std::vector<OrderBookProcessor::Trade>>* blocks)
			: m_blocks(blocks)
		{}
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
			std::ranges::sort(this->m_current_block, comp);
			this->m_blocks->push_back(this->m_current_block);
		}

		void process_trade(OrderBookProcessor::Trade const& trade) override
		{
			this->m_current_block.push_back(trade);
		}
	};

	TEST(InvalidAPIUsage, DoubleConnect)
	{
		Engine engine;
		engine.start();
		auto const connection = engine.create_connection();
		connection->connect("admin", "admin", "admin");
		EXPECT_ANY_THROW(connection->connect("admin", "admin", "admin"));
	}

	TEST(InvalidAPIUsage, DoubleStart)
	{
		Engine engine;
		engine.start();
		
		auto const connection = engine.create_connection();
		connection->connect("admin", "admin", "admin");
		EXPECT_ANY_THROW(engine.start());

	}

	TEST(InvalidAPIUsage, OrderWithInvalidSize)
	{
		Engine engine;
		engine.start();
		auto const connection = engine.create_connection();
		connection->connect("admin", "admin", "admin");
		EXPECT_ANY_THROW(connection->place_buy_order("B", -1, 10));
		EXPECT_ANY_THROW(connection->place_buy_order("B", 0, 10));
		EXPECT_ANY_THROW(connection->place_sell_order("S", -1, 10));
		EXPECT_ANY_THROW(connection->place_sell_order("S", 0, 10));
	}

	TEST(InvalidAPIUsage, OrderWithInvalidPrice)
	{
		Engine engine;
		engine.start();
		auto const connection = engine.create_connection();
		connection->connect("admin", "admin", "admin");
		EXPECT_ANY_THROW(connection->place_buy_order("B", 1, -1));
		EXPECT_ANY_THROW(connection->place_buy_order("B", 1, 0));
		EXPECT_ANY_THROW(connection->place_sell_order("S", 1, -1));
		EXPECT_ANY_THROW(connection->place_sell_order("S", 1, 0));
	}
}

#endif