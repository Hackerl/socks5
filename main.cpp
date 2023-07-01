#include <aio/net/stream.h>
#include <aio/net/dgram.h>
#include <aio/net/dns.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/net.h>

using namespace std::chrono_literals;

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("ip", "listen ip");
    cmdline.add<unsigned short>("port", "bind port");
    cmdline.addOptional<std::string>("username", '\0', "auth username");
    cmdline.addOptional<std::string>("password", '\0', "auth password");

    cmdline.parse(argc, argv);

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return -1;
    }
#endif

    auto ip = cmdline.get<std::string>("ip");
    auto port = cmdline.get<unsigned short>("port");
    auto username = cmdline.getOptional<std::string>("username");
    auto password = cmdline.getOptional<std::string>("password");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context)
        return -1;

    zero::ptr::RefPtr<aio::net::stream::Listener> listener = aio::net::stream::listen(context, ip, port);

    if (!listener)
        return -1;

    zero::async::promise::loop<void>([=](const auto &loop) {
        listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
                if (data[0] != std::byte{5})
                    return zero::async::promise::reject<std::vector<std::byte>>({-1, "unsupported version"});

                return buffer->readExactly(std::to_integer<size_t>(data[1]));
            })->then([=](nonstd::span<const std::byte> data) {
                if (!username || !password) {
                    auto response = {std::byte{5}, std::byte{0}};
                    return buffer->write(response);
                }

                if (std::find(data.begin(), data.end(), std::byte{2}) == data.end()) {
                    auto response = {std::byte{5}, std::byte{0xff}};
                    return buffer->write(response)->then([]() {
                        return zero::async::promise::reject<void>({-1, "unsupported method"});
                    });
                }

                auto response = {std::byte{5}, std::byte{2}};

                return buffer->write(response)->then([=]() {
                    return buffer->readExactly(1);
                })->then([=](nonstd::span<const std::byte> data) {
                    if (data[0] != std::byte{1}) {
                        auto response = {std::byte{1}, std::byte{1}};
                        return buffer->write(response)->then([]() {
                            return zero::async::promise::reject<void>({-1, "unsupported auth version"});
                        });
                    }

                    return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                        return buffer->readExactly(std::to_integer<size_t>(data[0]));
                    })->then([=](nonstd::span<const std::byte> data) {
                        if (std::string_view{(const char *) data.data(), data.size()} != *username) {
                            auto response = {std::byte{1}, std::byte{1}};
                            return buffer->write(response)->then([]() {
                                return zero::async::promise::reject<std::vector<std::byte>>({-1, "auth failed"});
                            });
                        }

                        return buffer->readExactly(1);
                    })->then([=](nonstd::span<const std::byte> data) {
                        return buffer->readExactly(std::to_integer<size_t>(data[0]));
                    })->then([=](nonstd::span<const std::byte> data) {
                        if (std::string_view{(const char *) data.data(), data.size()} != *password) {
                            auto response = {std::byte{1}, std::byte{1}};
                            return buffer->write(response)->then([]() {
                                return zero::async::promise::reject<void>({-1, "auth failed"});
                            });
                        }

                        auto response = {std::byte{1}, std::byte{0}};
                        return buffer->write(response);
                    });
                });
            })->then([=]() {
                return buffer->readExactly(4);
            })->then([=](nonstd::span<const std::byte> data) {
                if (data[0] != std::byte{5})
                    return zero::async::promise::reject<std::tuple<int, std::string, unsigned short>>(
                            {-1, "unsupported version"}
                    );

                std::shared_ptr<zero::async::promise::Promise<std::tuple<std::string, unsigned short>>> promise;

                switch (std::to_integer<int>(data[3])) {
                    case 1:
                        promise = buffer->readExactly(4)->then([=](nonstd::span<const std::byte, 4> data) {
                            return buffer->readExactly(2)->then(
                                    [ip = zero::os::net::stringify(data)](nonstd::span<const std::byte> data) {
                                        return std::tuple{ip, ntohs(*(uint16_t *) data.data())};
                                    }
                            );
                        });

                        break;

                    case 3:
                        promise = buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                            return buffer->readExactly(std::to_integer<size_t>(data[0]));
                        })->then([=](nonstd::span<const std::byte> data) {
                            return buffer->readExactly(2)->then(
                                    [
                                            host = std::string{(const char *) data.data(), data.size()}
                                    ](nonstd::span<const std::byte> data) {
                                        return std::tuple{host, ntohs(*(uint16_t *) data.data())};
                                    }
                            );
                        });

                        break;

                    case 4:
                        promise = buffer->readExactly(16)->then([=](nonstd::span<const std::byte, 16> data) {
                            return buffer->readExactly(2)->then(
                                    [ip = zero::os::net::stringify(data)](nonstd::span<const std::byte> data) {
                                        return std::tuple{ip, ntohs(*(uint16_t *) data.data())};
                                    }
                            );
                        });

                        break;

                    default:
                        break;
                }

                if (!promise)
                    return zero::async::promise::reject<std::tuple<int, std::string, unsigned short>>(
                            {-1, "unsupported address type"}
                    );

                return promise->then([=](std::string_view host, unsigned short port) {
                    return std::tuple<int, std::string, unsigned short>{std::to_integer<int>(data[1]), host, port};
                });
            })->then([=](int command, const std::string &host, unsigned short port) {
                std::shared_ptr<zero::async::promise::Promise<void>> promise;

                switch (command) {
                    case 1: {
                        LOG_INFO("TCP proxy: %s:%hu", host.c_str(), port);

                        auto response = {
                                std::byte{5},
                                std::byte{0},
                                std::byte{0},
                                std::byte{1},
                                std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                                std::byte{0}, std::byte{0}
                        };

                        promise = buffer->write(response)->then([=]() {
                            return aio::net::stream::connect(context, host, port);
                        })->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
                            return aio::tunnel(buffer, remote)->finally([=]() {
                                remote->close();
                            });
                        });

                        break;
                    }

                    case 3: {
                        zero::ptr::RefPtr<aio::net::dgram::Socket> socket = aio::net::dgram::bind(
                                context,
                                "0.0.0.0",
                                0
                        );

                        if (!socket)
                            break;

                        std::optional<aio::net::Address> address = socket->localAddress();

                        if (!address || address->index() != 0)
                            break;

                        aio::net::IPv4Address ipv4Address = std::get<aio::net::IPv4Address>(*address);
                        unsigned short bindPort = htons(ipv4Address.port);

                        std::vector<std::byte> response = {std::byte{5}, std::byte{0}, std::byte{0}, std::byte{1}};

                        response.insert(response.end(), ipv4Address.ip, ipv4Address.ip + 4);
                        response.insert(
                                response.end(),
                                (const std::byte *) &bindPort,
                                (const std::byte *) &bindPort + sizeof(unsigned short)
                        );

                        LOG_INFO(
                                "UDP proxy: %s:%hu <=> %s:%hu",
                                zero::os::net::stringify(ipv4Address.ip).c_str(),
                                ipv4Address.port,
                                host.c_str(),
                                port
                        );

                        promise = buffer->write(response)->then([=]() {
                            socket->setTimeout(1min, 0ms);
                            std::shared_ptr<std::optional<aio::net::IPv4Address>> address = std::make_shared<std::optional<aio::net::IPv4Address>>();

                            return zero::async::promise::loop<void>([=](const auto &loop) {
                                socket->readFrom(10240)->then(
                                        [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                            aio::net::IPv4Address fromAddress = std::get<aio::net::IPv4Address>(from);

                                            if (!*address)
                                                *address = fromAddress;

                                            if (memcmp(fromAddress.ip, address.operator*()->ip, 4) != 0 ||
                                                fromAddress.port != address.operator*()->port) {
                                                unsigned short port = htons(fromAddress.port);

                                                std::vector<std::byte> response = {
                                                        std::byte{0}, std::byte{0},
                                                        std::byte{0},
                                                        std::byte{1}
                                                };

                                                response.insert(response.end(), fromAddress.ip, fromAddress.ip + 4);
                                                response.insert(
                                                        response.end(),
                                                        (const std::byte *) &port,
                                                        (const std::byte *) &port + sizeof(unsigned short)
                                                );

                                                response.insert(response.end(), data.begin(), data.end());

                                                return socket->writeTo(response, **address);
                                            }

                                            if (data[2] != std::byte{0}) {
                                                return zero::async::promise::reject<void>(
                                                        {-1, "fragmentation is not supported"}
                                                );
                                            }

                                            std::optional<std::string> host;
                                            std::optional<unsigned short> port;
                                            nonstd::span<const std::byte> payload;

                                            switch (std::to_integer<int>(data[3])) {
                                                case 1:
                                                    host = zero::os::net::stringify(data.subspan<4, 4>());
                                                    port = ntohs(*(uint16_t *) (data.data() + 8));
                                                    payload = data.subspan(10);
                                                    break;

                                                case 3: {
                                                    auto length = std::to_integer<size_t>(data[4]);

                                                    host = std::string{(const char *) data.data() + 5, length};
                                                    port = ntohs(*(uint16_t *) (data.data() + 5 + length));
                                                    payload = data.subspan(7 + length);

                                                    break;
                                                }

                                                case 4:
                                                    host = zero::os::net::stringify(data.subspan<4, 16>());
                                                    port = ntohs(*(uint16_t *) (data.data() + 20));
                                                    payload = data.subspan(22);

                                                    break;

                                                default:
                                                    break;
                                            }

                                            if (!host || !port)
                                                return zero::async::promise::reject<void>(
                                                        {-1, "unsupported address type"}
                                                );

                                            evutil_addrinfo hints = {};

                                            hints.ai_family = AF_INET;
                                            hints.ai_socktype = SOCK_DGRAM;

                                            return aio::net::dns::lookup(
                                                    context,
                                                    *host,
                                                    std::to_string(*port),
                                                    hints
                                            )->then([=](nonstd::span<const aio::net::Address> records) {
                                                return socket->writeTo(payload, records.front());
                                            });
                                        }
                                )->then([=]() {
                                    P_CONTINUE(loop);
                                }, [=](const zero::async::promise::Reason &reason) {
                                    P_BREAK_E(loop, reason);
                                });
                            });
                        });

                        break;
                    }

                    default:
                        break;
                }

                if (!promise)
                    return zero::async::promise::reject<void>({-1, "unsupported command"});

                return promise;
            })->fail([](const zero::async::promise::Reason &reason) {
                LOG_INFO("%s", reason.message.c_str());
            })->finally([=]() {
                buffer->close();
            });
        })->then([=]() {
            P_CONTINUE(loop);
        }, [=](const zero::async::promise::Reason &reason) {
            P_BREAK_E(loop, reason);
        });
    })->fail([](const zero::async::promise::Reason &reason) {
        LOG_ERROR("%s", reason.message.c_str());
    })->finally([=]() {
        context->loopBreak();
    });

    context->dispatch();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
