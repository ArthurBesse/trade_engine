#ifndef LIBENGINE_ENGINE_H
#define LIBENGINE_ENGINE_H

#include <chrono>
#include <future>
#include <thread>
#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <libengine/OrderBookProcessor.h>
#include <libengine/Connection.h>

class Engine final
{
	friend class Connection;
	friend class ConnectionManager;

	using clock_t = OrderBookProcessor::Order::clock_t;
	using time_point_t = OrderBookProcessor::Order::time_point_t;
	using order_type_t = OrderBookProcessor::Order::order_type_t;

public:
	Engine();
	Engine(Engine const&) = delete;
	Engine(Engine &&) = delete;
	Engine& operator=(Engine const&) = delete;
	Engine& operator=(Engine &&) = delete;
	~Engine();

	Connection* create_connection();
	void start();
	bool stop();
	void finalize() const;

private:
	struct job_t
	{
		std::jthread m_thread;
		std::shared_ptr<std::promise<void>> m_promise;
		std::future<void> m_future;
		std::atomic_flag m_running_flag;
		std::atomic_flag m_stoppable_flag;

		job_t() = default;
		job_t(job_t const&) = delete;
		job_t(job_t&&) = delete;
		job_t& operator=(job_t const&) = delete;
		job_t& operator=(job_t&&) = delete;
		~job_t() = default;

		void start(std::function<void(std::stop_token const&, std::reference_wrapper<std::atomic_flag>)> const& task);
		void stop();
	};

	job_t m_order_processor_job;
	job_t m_trade_processor_job;
	
	boost::lockfree::queue<OrderBookProcessor::Order> m_pending_orders;
	boost::lockfree::queue<OrderBookProcessor::Trade> m_processed_trades;
	ConnectionManager m_connection_manager;
	OrderBookProcessor m_order_book_processor;
};



#endif
