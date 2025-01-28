#ifndef LIBENGINE_BASIC_FUNCTIONALITY_TESTS_H
#define LIBENGINE_BASIC_FUNCTIONALITY_TESTS_H
#include <gtest/gtest.h>
#include <libengine/Engine.h>

namespace basic_functionality_tests
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

	TEST(BasicFunctinality, test1)
	{
		Engine engine;
		engine.start();

		std::vector<std::vector<OrderBookProcessor::Trade>> data;
		auto const  connection = engine.create_connection();
		auto subscription = std::make_unique<Subscription>(&data);
		connection->connect("admin", "admin", "admin");
		connection->subscribe_for_updates(std::move(subscription));

		connection->place_buy_order("U1", 3, 10);
		connection->place_sell_order("U2", 3, 10);

		connection->place_buy_order("U2", 3, 10);
		connection->place_sell_order("U1", 3, 10);


		engine.finalize();
		auto const res = engine.stop();

		ASSERT_TRUE(res);
		ASSERT_EQ(data.size(), 2);


		{
			auto const& block1 = data[0];
			ASSERT_EQ(block1.size(), 2);
			auto const& buy_trade = block1[0];
			auto const& sell_trade = block1[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "U1");
			EXPECT_EQ(buy_trade.m_size, 3);
			EXPECT_EQ(buy_trade.m_price, 10);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "U2");
			EXPECT_EQ(sell_trade.m_size, 3);
			EXPECT_EQ(sell_trade.m_price, 10);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}

		{
			auto const& block2 = data[1];
			ASSERT_EQ(block2.size(), 2);
			auto const& buy_trade = block2[1];
			auto const& sell_trade = block2[0];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "U2");
			EXPECT_EQ(buy_trade.m_size, 3);
			EXPECT_EQ(buy_trade.m_price, 10);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "U1");
			EXPECT_EQ(sell_trade.m_size, 3);
			EXPECT_EQ(sell_trade.m_price, 10);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}
	}

	TEST(BasicFunctinality, test2)
	{
		Engine engine;
		engine.start();

		std::vector<std::vector<OrderBookProcessor::Trade>> data;
		auto const  connection = engine.create_connection();
		auto subscription = std::make_unique<Subscription>(&data);
		connection->connect("admin", "admin", "admin");
		connection->subscribe_for_updates(std::move(subscription));

		connection->place_buy_order("U1", 3, 10);
		connection->place_sell_order("U2", 3, 5);

		connection->place_buy_order("U2", 3, 10);
		connection->place_sell_order("U1", 3, 5);


		engine.finalize();
		auto const res = engine.stop();

		ASSERT_TRUE(res);
		ASSERT_EQ(data.size(), 2);


		{
			auto const& block1 = data[0];
			ASSERT_EQ(block1.size(), 2);
			auto const& buy_trade = block1[0];
			auto const& sell_trade = block1[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "U1");
			EXPECT_EQ(buy_trade.m_size, 3);
			EXPECT_EQ(buy_trade.m_price, 10);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "U2");
			EXPECT_EQ(sell_trade.m_size, 3);
			EXPECT_EQ(sell_trade.m_price, 10);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}

		{
			auto const& block2 = data[1];
			ASSERT_EQ(block2.size(), 2);
			auto const& buy_trade = block2[1];
			auto const& sell_trade = block2[0];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "U2");
			EXPECT_EQ(buy_trade.m_size, 3);
			EXPECT_EQ(buy_trade.m_price, 10);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "U1");
			EXPECT_EQ(sell_trade.m_size, 3);
			EXPECT_EQ(sell_trade.m_price, 10);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}
	}

	TEST(BasicFunctinality, test3)
	{
		Engine engine;
		engine.start();

		std::vector<std::vector<OrderBookProcessor::Trade>> data;
		auto const  connection = engine.create_connection();
		auto subscription = std::make_unique<Subscription>(&data);
		connection->connect("admin", "admin", "admin");
		connection->subscribe_for_updates(std::move(subscription));

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


		engine.finalize();
		auto const res = engine.stop();

		ASSERT_TRUE(res);
		ASSERT_EQ(data.size(), 4);


		{
			auto const& block1 = data[0];
			ASSERT_EQ(block1.size(), 2);
			auto const& buy_trade = block1[0];
			auto const& sell_trade = block1[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "T1");
			EXPECT_EQ(buy_trade.m_size, 1);
			EXPECT_EQ(buy_trade.m_price, 50);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "T7");
			EXPECT_EQ(sell_trade.m_size, 1);
			EXPECT_EQ(sell_trade.m_price, 50);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}

		{
			auto const& block2 = data[1];
			ASSERT_EQ(block2.size(), 2);
			auto const& buy_trade = block2[0];
			auto const& sell_trade = block2[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "T1");
			EXPECT_EQ(buy_trade.m_size, 2);
			EXPECT_EQ(buy_trade.m_price, 60);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "T4");
			EXPECT_EQ(sell_trade.m_size, 2);
			EXPECT_EQ(sell_trade.m_price, 60);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}

		{
			auto const& block3 = data[2];
			ASSERT_EQ(block3.size(), 2);
			auto const& buy_trade = block3[0];
			auto const& sell_trade = block3[1];
			auto const buy_user = buy_trade.m_user_info.get_username();
			auto const sell_user = sell_trade.m_user_info.get_username();

			EXPECT_STREQ(buy_user.data(), "T1");
			EXPECT_EQ(buy_trade.m_size, 1);
			EXPECT_EQ(buy_trade.m_price, 60);
			EXPECT_EQ(buy_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);


			EXPECT_STREQ(sell_user.data(), "T7");
			EXPECT_EQ(sell_trade.m_size, 1);
			EXPECT_EQ(sell_trade.m_price, 60);
			EXPECT_EQ(sell_trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
		}

		{
			auto const& block4 = data[3];
			ASSERT_EQ(block4.size(), 8);

			{
				auto const& trade = block4[0];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T2");
				EXPECT_EQ(trade.m_size, 5);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
			}
			{
				auto const& trade = block4[1];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T2");
				EXPECT_EQ(trade.m_size, 1);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
			}
			{
				auto const& trade = block4[2];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T5");
				EXPECT_EQ(trade.m_size, 3);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
			}
			{
				auto const& trade = block4[3];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T7");
				EXPECT_EQ(trade.m_size, 1);
				EXPECT_EQ(trade.m_price, 50);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::SELL);
			}
			{
				auto const& trade = block4[4];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T8");
				EXPECT_EQ(trade.m_size, 1);
				EXPECT_EQ(trade.m_price, 50);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);
			}
			{
				auto const& trade = block4[5];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T8");
				EXPECT_EQ(trade.m_size, 5);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);
			}
			{
				auto const& trade = block4[6];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T8");
				EXPECT_EQ(trade.m_size, 3);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);
			}
			{
				auto const& trade = block4[7];
				auto const user = trade.m_user_info.get_username();
				EXPECT_STREQ(user.data(), "T8");
				EXPECT_EQ(trade.m_size, 1);
				EXPECT_EQ(trade.m_price, 70);
				EXPECT_EQ(trade.m_trade_type, OrderBookProcessor::Trade::trade_type_t::BUY);
			}
			
		}
	}

	
}

#endif