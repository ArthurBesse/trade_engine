#include <libengine/Engine.h>
#include <iostream>
#include <functional>
#include <print>

Engine::Engine()
	: m_pending_orders(1 << 10)
	, m_processed_trades(1 << 10)
	, m_connection_manager(this)
{
}

Engine::~Engine()
{
	this->stop();
}

Connection* Engine::create_connection()
{
	return this->m_connection_manager.create_connection();
}

void Engine::start()
{
	this->m_order_processor_job.start([this](std::stop_token const& token, std::reference_wrapper<std::atomic_flag> stoppable_flag)
		{
			OrderBookProcessor::Order current_order;
			while (true)
			{
				while (false == token.stop_requested() && true == this->m_pending_orders.empty());
				if (false == this->m_pending_orders.empty())
				{
					stoppable_flag.get().clear();
					this->m_pending_orders.pop(current_order);
					auto const trades = this->m_order_book_processor.process_order(current_order);
					std::ranges::for_each(trades, [this](auto const& trade) {this->m_processed_trades.push(trade); });
					stoppable_flag.get().test_and_set();
				}
				if (true == token.stop_requested()) break;
			}
		});

	this->m_trade_processor_job.start([this](std::stop_token const& token, std::reference_wrapper<std::atomic_flag> stoppable_flag)
		{
			OrderBookProcessor::Trade current_trade;
			std::vector<OrderBookProcessor::Trade> current_trade_block;
			bool block_started = false;
			while(true)
			{
				while (false == token.stop_requested() && true == this->m_processed_trades.empty());
				
				if (false == this->m_processed_trades.empty())
				{
					stoppable_flag.get().clear();
					this->m_processed_trades.pop(current_trade);
					if (current_trade.m_trade_type == OrderBookProcessor::Trade::trade_type_t::SPECIAL_BLOCK_START)
					{
						current_trade_block.clear();
						block_started = true;
					}
					else if (current_trade.m_trade_type == OrderBookProcessor::Trade::trade_type_t::SPECIAL_BLOCK_END)
					{
						block_started = false;
						this->m_connection_manager.process_trade_block(current_trade_block);
					}
					else if (true == block_started)
					{
						current_trade_block.push_back(current_trade);
					}
					stoppable_flag.get().test_and_set();
				}
				if (true == token.stop_requested()) break;
			}
		});
}

bool Engine::stop()
{
	bool result = true;
	try
	{
		this->m_order_processor_job.stop();
	}
	catch (std::exception const& e)
	{
		result = false;
		std::cerr << "Exception occurred in order processor thread: " << e.what() << std::endl;
	}
	try
	{
		this->m_trade_processor_job.stop();
	}
	catch (std::exception const& e)
	{
		result = false;
		std::cerr << "Exception occurred in trade processor thread: " << e.what() << std::endl;
	}
	return result;
}

void Engine::finalize() const
{
	while (false == this->m_pending_orders.empty() 
	|| false == this->m_processed_trades.empty()
	|| false == this->m_order_processor_job.m_stoppable_flag.test()
	|| false == this->m_trade_processor_job.m_stoppable_flag.test());
}

void Engine::job_t::start(std::function<void(std::stop_token const&, std::reference_wrapper<std::atomic_flag>)> const& task)
{
	if (this->m_running_flag.test() == true)
		throw std::logic_error("Failed to start engine: already started.");
	this->m_running_flag.test_and_set();
	this->m_promise = std::make_shared<std::promise<void>>();
	this->m_future = this->m_promise->get_future();
	std::packaged_task task_wrapper([this, task](std::stop_token const& token)
		{
			try
			{
				this->m_promise->set_value_at_thread_exit();
				task(token, std::ref(this->m_stoppable_flag));
			}
			catch (...)
			{
				try
				{
					this->m_promise->set_exception(std::current_exception());
				}
				catch (...) { std::terminate(); }
			}
		});
	this->m_thread = std::jthread(std::move(task_wrapper));
}

void Engine::job_t::stop()
{
	if (this->m_running_flag.test() == false) return;
	this->m_thread.request_stop();
	this->m_future.wait();
	this->m_future.get();
	this->m_running_flag.clear();
}
