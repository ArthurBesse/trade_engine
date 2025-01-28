#ifndef LIBENGINE_ORDER_BOOK_PROCESSOR_H
#define LIBENGINE_ORDER_BOOK_PROCESSOR_H

#include <array>
#include <chrono>
#include <queue>

class OrderBookProcessor final
{
public:
	struct user_info_t
	{
		std::array<char, 256> m_username;
		size_t m_username_size;
		user_info_t();
		[[nodiscard]] std::string_view get_username() const;
	};

	class Order final
	{
	public:
		using clock_t = std::chrono::high_resolution_clock;
		using time_point_t = std::chrono::time_point<clock_t>;
		enum class order_type_t { BID, ASK };
		user_info_t m_user_info;
		time_point_t m_time_point;
		order_type_t m_order_type;
		mutable int m_size;
		int m_price;

		Order();

		friend auto operator<=>(const Order& lhs, const Order& rhs)
		{
			if (lhs.m_price != rhs.m_price) return lhs.m_price <=> rhs.m_price;
			return lhs.m_time_point <=> rhs.m_time_point;
		}
	};

	class Trade final
	{
	public:
		enum class trade_type_t { BUY, SELL, SPECIAL_BLOCK_START, SPECIAL_BLOCK_END };
		Trade();
		Trade(user_info_t const& user_info, trade_type_t trade_type, int size, int price);
		user_info_t m_user_info;
		trade_type_t m_trade_type;
		mutable int m_size;
		int m_price;
	};

	template <template<class> class Comp>
	using ob_side = std::priority_queue<Order, std::vector<Order>, Comp<Order>>;
	using bids_t = ob_side<std::less>;
	using asks_t = ob_side<std::greater>;

	OrderBookProcessor() = default;
	OrderBookProcessor(OrderBookProcessor const&) = delete;
	OrderBookProcessor(OrderBookProcessor&&) = delete;
	OrderBookProcessor& operator=(OrderBookProcessor const&) = delete;
	OrderBookProcessor& operator=(OrderBookProcessor&&) = delete;
	~OrderBookProcessor() = default;

	[[nodiscard]] bids_t const& get_bids() const;
	[[nodiscard]] asks_t const& get_asks() const;

	std::vector<Trade> process_order(Order order);

private:
	bids_t m_bids;
	asks_t m_asks;
};


#endif