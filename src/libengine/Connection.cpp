#include <libengine/Connection.h>
#include <libengine/Engine.h>

Connection::Connection(ConnectionManager* manager, int const id)
	: m_status(status_t::DISCONNECTED)
	, m_manager(manager)
	, m_id(id)
{
}


void Connection::connect(user_credentials_t const& user_credentials)
{
	if (this->m_status == status_t::CONNECTED)
		throw std::logic_error("Connection: " + std::to_string(this->m_id) + ": Failed to connect: already connected.");

	this->m_manager->register_connection(this->shared_from_this());
	this->m_status = status_t::CONNECTED;
	this->m_user_credentials = user_credentials;
}

void Connection::connect(std::string username, std::string public_key, std::string private_key)
{		
	this->connect({ std::move(public_key), std::move(private_key), std::move(username) });
}

void Connection::place_buy_order(std::string const& username, const int size, const int price)
{
	if (this->m_status == status_t::DISCONNECTED)
		throw std::logic_error("Connection: " + std::to_string(this->m_id) + ": Failed to process order: disconnected.");

	this->m_manager->place_order(this->shared_from_this(), username, OrderBookProcessor::Order::order_type_t::BID, size, price);
}

void Connection::place_sell_order(std::string const& username, const int size, const int price)
{
	if (this->m_status == status_t::DISCONNECTED)
		throw std::logic_error("Connection: " + std::to_string(this->m_id) + ": Failed to process order: disconnected.");

	this->m_manager->place_order(this->shared_from_this(), username, OrderBookProcessor::Order::order_type_t::ASK, size, price);
}

void Connection::subscribe_for_updates(std::unique_ptr<Subscription> subscription)
{
	if (this->m_status == status_t::DISCONNECTED)
		throw std::logic_error("Connection: " + std::to_string(this->m_id) + ": Failed to subscribe for updates: disconnected.");

	this->m_subscription = std::move(subscription);
	this->m_manager->register_subscription(this->shared_from_this());
}

void Connection::unsubscribe()
{
	if(false == this->has_active_subscription())
		throw std::logic_error("Connection: " + std::to_string(this->m_id) + ": Failed to unsubscribe for updates: no active subscription.");

	this->m_manager->close_subscription(this->shared_from_this());
}

void Connection::disconnect()
{
	if (this->m_status == status_t::DISCONNECTED) return;
	this->m_status = status_t::DISCONNECTED;
	if (this->has_active_subscription()) this->unsubscribe();
	this->m_manager->close_connection(this->m_id);
}

int Connection::get_id() const
{
	return this->m_id;
}

bool Connection::has_active_subscription() const
{
	if (this->m_subscription) return true;
	return false;
}

Connection::status_t Connection::get_status() const
{
	return this->m_status;
}

Connection::user_credentials_t const& Connection::get_user_credentials() const
{
	return this->m_user_credentials;
}


ConnectionManager::ConnectionManager(Engine* engine)
	: m_engine(engine)
{
}

Connection* ConnectionManager::create_connection()
{
	std::scoped_lock lock(this->m_connection_mutex);
	int const connection_id = construct_new_connection_id();
	auto connection = std::make_shared<Connection>(this, connection_id);
	this->m_active_connections.emplace(connection_id, connection);
	return connection.get();
}


bool ConnectionManager::perform_authentication(std::shared_ptr<Connection> const& connection)
{
	//TODO: to be extended
	return true;
}

void ConnectionManager::process_trade_block(std::vector<OrderBookProcessor::Trade> const& block)
{
	std::scoped_lock lock(this->m_subscription_mutex);
	for(auto const& [id, connection]: this->m_active_connections_with_subscriptions)
		connection->m_subscription->process_block_start();

	for (auto const& [id, connection]: this->m_active_connections_with_subscriptions)
	{
		for (auto const& trade : block)
			connection->m_subscription->process_trade(trade);
	}

	for (auto const& [id, connection]: this->m_active_connections_with_subscriptions )
		connection->m_subscription->process_block_end();
}

void ConnectionManager::register_connection(std::shared_ptr<Connection> const& connection)
{
	{
		std::scoped_lock lock(this->m_connection_mutex);
		if (false == this->m_active_connections.contains(connection->get_id()))
			throw std::logic_error("Connection: " + std::to_string(connection->m_id) + ": Failed to register connection: connection is destroyed.");
	}

	auto const authentication_result = this->perform_authentication(connection);
	if (false == authentication_result)
		throw std::runtime_error("Connection: " + std::to_string(connection->m_id) + ": Authentication failed");
}


void ConnectionManager::register_subscription(std::shared_ptr<Connection> const& connection)
{
	if (connection->has_active_subscription())
	{
		std::scoped_lock lock(this->m_subscription_mutex);
		this->m_active_connections_with_subscriptions.emplace(connection->m_id, connection);
	}
}

void ConnectionManager::close_connection(int const connection_id)
{
	std::scoped_lock lock(this->m_connection_mutex);
	this->m_active_connections.erase(connection_id);
}

void ConnectionManager::close_subscription(std::shared_ptr<Connection> const& connection)
{
	if (connection->has_active_subscription())
	{
		std::scoped_lock lock(this->m_subscription_mutex);
		this->m_active_connections_with_subscriptions.erase(connection->m_id);
	}
}

void ConnectionManager::place_order(std::shared_ptr<Connection> const& connection, std::string const& username,
                                    order_type_t const order_type, int const size, int const price) const
{
	if (username.size() > 255)
		throw std::invalid_argument("Connection: " + std::to_string(connection->m_id) + ": Failed to process order: user name is too long, maximum accepted length is 255.");

	if(size <= 0)
		throw std::invalid_argument("Connection: " + std::to_string(connection->m_id) + ": Failed to process order: order size should be positive.");

	if (price <= 0)
		throw std::invalid_argument("Connection: " + std::to_string(connection->m_id) + ": Failed to process order: order price should be positive.");

	OrderBookProcessor::Order order;
	std::ranges::copy(username, order.m_user_info.m_username.begin());
	order.m_user_info.m_username_size = username.size();
	order.m_order_type = order_type;
	order.m_price = price;
	order.m_size = size;
	order.m_time_point = ConnectionManager::clock_t::now();
	this->m_engine->m_pending_orders.push(order);
}

int ConnectionManager::construct_new_connection_id()
{
	static std::atomic_int id = 0;
	return ++id;
}