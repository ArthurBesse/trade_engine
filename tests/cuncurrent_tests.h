#ifndef LIBENGINE_CONCURRENT_TESTS_H
#define LIBENGINE_CONCURRENT_TESTS_H
#include <random>
#include <gtest/gtest.h>
#include <libengine/Engine.h>

namespace concurrent_tests
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

	TEST(Concurrent, TwoConnections)
	{
		Engine engine;
		engine.start();
		auto const buy_future = std::async(std::launch::async, [&engine]()
			{
				auto const connection = engine.create_connection();
				connection->connect("admin", "admin", "admin");
				connection->place_buy_order("U1", 10, 20);
				connection->disconnect();
			});

		auto const sell_future = std::async(std::launch::async, [&engine]()
			{
				auto const connection = engine.create_connection();
				connection->connect("admin", "admin", "admin");
				connection->place_sell_order("U2", 5, 20);
				connection->disconnect();
			});

		std::vector<std::vector<OrderBookProcessor::Trade>> data;
		auto const  connection = engine.create_connection();
		auto subscription = std::make_unique<Subscription>(&data);
		connection->connect("admin", "admin", "admin");
		connection->subscribe_for_updates(std::move(subscription));

		
		buy_future.wait();
		sell_future.wait();
		engine.finalize();
		auto const res = engine.stop();

		ASSERT_TRUE(res);
		ASSERT_EQ(data.size(), 1);

		{
			auto const& block1 = data[0];
			ASSERT_EQ(block1.size(), 2);
			auto const& buy_trade = block1[0];
			auto const& sell_trade = block1[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "U1");
			EXPECT_EQ(buy_trade.m_size, 5);
			EXPECT_EQ(buy_trade.m_price, 20);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "U2");
			EXPECT_EQ(sell_trade.m_size, 5);
			EXPECT_EQ(sell_trade.m_price, 20);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}
	}

	TEST(Concurrent, MultipleThreads)
	{
		Engine engine;
		engine.start();
		std::mt19937 rng(42);
		std::array<std::future<void>, 20> buy_futures;
		std::array<std::future<void>, 20> sell_futures;
		for(int i = 0; i < 20; ++i)
		{
			buy_futures[i] = std::async(std::launch::async, [&engine, i]()
				{
					auto pseudo_rand = [](int i)
						{
							constexpr int a = 1664525;
							constexpr int c = 1013904223;
							constexpr int m = 1 << 31;
							return (a * i + c) % m;
						};

					auto const connection = engine.create_connection();
					auto const eps_price = (pseudo_rand(i) % 14) - 7;
					auto const eps_size = (pseudo_rand(i) % 10) - 5;

					connection->connect("admin", "admin", "admin");
					connection->place_buy_order("B" + std::to_string(i + 1), 10 + eps_size, 20 + eps_price);
					connection->disconnect();
				});
		}

		for (int i = 0; i < 20; ++i)
		{
			sell_futures[i] = std::async(std::launch::async, [&engine, i]()
				{
					auto pseudo_rand = [](int i)
						{
							constexpr int a = 1664525;
							constexpr int c = 1013904223;
							constexpr int m = 1 << 31;
							return (a * i + c) % m;
						};

					auto const connection = engine.create_connection();
					auto const eps_price = (pseudo_rand(i) % 14) - 7;
					auto const eps_size = (pseudo_rand(i) % 10) - 5;

					connection->connect("admin", "admin", "admin");
					connection->place_sell_order("S" + std::to_string(i + 1), 10 + eps_size, 20 + eps_price);
					connection->disconnect();
				});
		}


		std::vector<std::vector<OrderBookProcessor::Trade>> data;
		auto const  connection = engine.create_connection();
		auto subscription = std::make_unique<Subscription>(&data);
		connection->connect("admin", "admin", "admin");
		connection->subscribe_for_updates(std::move(subscription));

		for (auto const& f : buy_futures) f.wait();
		for (auto const& f : sell_futures) f.wait();

		engine.finalize();
		auto const res = engine.stop();

		ASSERT_TRUE(res);
	}

	TEST(InvalidAPIUsage, DoubleStart)
	{
		Engine engine;
		engine.start();
		
		auto const connection = engine.create_connection();
		connection->connect("admin", "admin", "admin");
		EXPECT_ANY_THROW(engine.start());

	}
}

#endif