#include <libengine/OrderBookProcessor.h>

OrderBookProcessor::Order::Order()
	: m_order_type()
	, m_size(0)
	, m_price(0)
{
}

OrderBookProcessor::Trade::Trade()
	: m_trade_type()
	, m_size(0)
	, m_price(0)
{
}

OrderBookProcessor::Trade::Trade(user_info_t const& user_info, const trade_type_t trade_type, const int size, const int price)
	: m_user_info(user_info)
	, m_trade_type(trade_type)
	, m_size(size)
	, m_price(price)
{
}

OrderBookProcessor::bids_t const& OrderBookProcessor::get_bids() const
{
	return this->m_bids;
}

OrderBookProcessor::asks_t const& OrderBookProcessor::get_asks() const
{
	return this->m_asks;
}

std::vector<OrderBookProcessor::Trade> OrderBookProcessor::process_order(Order order)
{
	std::vector<Trade> result;
	result.emplace_back(user_info_t{}, Trade::trade_type_t::SPECIAL_BLOCK_START, 0, 0);
	if (order.m_order_type == Order::order_type_t::BID)
	{
		while(true)
		{
			if (order.m_size == 0) break;
			if(true == this->m_asks.empty())
			{
				this->m_bids.push(order);
				break;
			}

			auto const& best_ask = this->m_asks.top();
			if(order.m_price < best_ask.m_price)
			{
				this->m_bids.push(order);
				break;
			}
			
			auto const size = std::min(order.m_size, best_ask.m_size);
			auto const price = best_ask.m_price;

			result.emplace_back(order.m_user_info, Trade::trade_type_t::BUY, size, price);
			result.emplace_back(best_ask.m_user_info, Trade::trade_type_t::SELL, size, price);

			order.m_size -= size;
			best_ask.m_size -= size;

			if (best_ask.m_size == 0) this->m_asks.pop();
		}
	}
	else
	{
		while (true)
		{
			if (order.m_size == 0) break;
			if (true == this->m_bids.empty())
			{
				this->m_asks.push(order);
				break;
			}


			auto const& best_bid = this->m_bids.top();
			if (order.m_price > best_bid.m_price)
			{
				this->m_asks.push(order);
				break;
			}
			
			auto const size = std::min(order.m_size, best_bid.m_size);
			auto const price = best_bid.m_price;

			result.emplace_back(order.m_user_info, Trade::trade_type_t::SELL, size, price);
			result.emplace_back(best_bid.m_user_info, Trade::trade_type_t::BUY, size, price);

			order.m_size -= size;
			best_bid.m_size -= size;

			if (best_bid.m_size == 0) this->m_bids.pop();
		}
	}
	result.emplace_back(user_info_t{}, Trade::trade_type_t::SPECIAL_BLOCK_END, 0, 0);
	if (result.size() == 2) result.clear();
	return result;
}

OrderBookProcessor::user_info_t::user_info_t()
	: m_username()
	, m_username_size(0)
{

}

std::string_view OrderBookProcessor::user_info_t::get_username() const
{
	return std::string_view(this->m_username.data(), this->m_username_size);
}
