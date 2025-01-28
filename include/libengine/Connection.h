#ifndef LIBENGINE_CONNECTION_H
#define LIBENGINE_CONNECTION_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <libengine/OrderBookProcessor.h>

class ConnectionManager;
class Engine;

class Connection final : public std::enable_shared_from_this<Connection>
{
	friend class ConnectionManager;

public:
	struct user_credentials_t
	{
		std::string m_public_key;
		std::string m_private_key;
		std::string m_username;
	};

	class Subscription
	{
	public:
		virtual void process_block_start() = 0;
		virtual void process_block_end() = 0;
		virtual void process_trade(OrderBookProcessor::Trade const& trade) = 0;

		Subscription() = default;
		Subscription(Subscription const&) = delete;
		Subscription(Subscription&&) = delete;
		Subscription& operator=(Subscription const&) = delete;
		Subscription& operator=(Subscription&&) = delete;
		virtual ~Subscription() = default;
	};

	enum class status_t { DISCONNECTED, CONNECTED };

	void connect(user_credentials_t const& user_credentials);
	void connect(std::string username, std::string public_key, std::string private_key);
	void place_buy_order(std::string const& username, int size, int price);
	void place_sell_order(std::string const& username, int size, int price);
	void subscribe_for_updates(std::unique_ptr<Subscription> subscription);
	void unsubscribe();

	[[nodiscard]] int get_id() const;
	[[nodiscard]] bool has_active_subscription() const;
	[[nodiscard]] status_t get_status() const;
	[[nodiscard]] user_credentials_t const& get_user_credentials() const;

	void disconnect();

	Connection(ConnectionManager* manager, int id);
	Connection(Connection const&) = delete;
	Connection(Connection &&) = delete;
	Connection& operator=(Connection const&) = delete;
	Connection& operator=(Connection &&) = delete;
	~Connection() = default;

private:

	user_credentials_t m_user_credentials;
	status_t m_status;
	ConnectionManager* m_manager;
	std::shared_ptr<Subscription> m_subscription;
	int m_id;
};

class ConnectionManager final
{
	friend class Engine;
	friend class Connetion;

	using clock_t = OrderBookProcessor::Order::clock_t;
	using time_point_t = OrderBookProcessor::Order::time_point_t;
	using order_type_t = OrderBookProcessor::Order::order_type_t;

	explicit ConnectionManager(Engine* engine);

	[[nodiscard]] Connection* create_connection();
	[[nodiscard]] bool perform_authentication(std::shared_ptr<Connection> const& connections);

	void process_trade_block(std::vector<OrderBookProcessor::Trade> const& block);

public:
	void place_order(std::shared_ptr<Connection> const& connection, std::string const& username, order_type_t order_type, int size, int price) const;
	void register_connection(std::shared_ptr<Connection> const& connection);
	void register_subscription(std::shared_ptr<Connection> const& connection);
	void close_connection(int const connection_id);
	void close_subscription(std::shared_ptr<Connection> const& connection);

private:
	Engine* m_engine;
	std::mutex m_connection_mutex;
	std::mutex m_subscription_mutex;
	std::unordered_map<int, std::shared_ptr<Connection>> m_active_connections_with_subscriptions;
	std::unordered_map<int, std::shared_ptr<Connection>> m_active_connections;
	static int construct_new_connection_id();
};


#endif
