#include <boost/asio/ip/tcp.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>


using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;


// Handles an HTTP server connection
void do_session(tcp::socket& socket, std::shared_ptr<std::string const> const& doc_root);