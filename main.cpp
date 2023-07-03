#include <aio/net/stream.h>
#include <aio/net/dgram.h>
#include <aio/net/dns.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/net.h>

struct User {
    std::string username;
    std::string password;
};

template<>
std::optional<User> zero::convert<User>(std::string_view str) {
    std::vector<std::string> tokens = zero::strings::split(str, ":");

    if (tokens.size() != 2)
        return std::nullopt;

    return User{zero::strings::trim(tokens[0]), zero::strings::trim(tokens[1])};
}

struct HostAddress {
    unsigned short port;
    std::string hostname;
};

using Target = std::variant<HostAddress, aio::net::IPv4Address, aio::net::IPv6Address>;

std::string stringify(const Target &target) {
    std::string result;

    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);
            result = address.hostname + ":" + std::to_string(address.port);
            break;
        }

        case 1: {
            auto address = std::get<aio::net::IPv4Address>(target);
            result = zero::os::net::stringify(address.ip) + ":" + std::to_string(address.port);
            break;
        }

        case 2: {
            auto address = std::get<aio::net::IPv6Address>(target);
            result = zero::os::net::stringify(address.ip) + ":" + std::to_string(address.port);
            break;
        }
    }

    return result;
}

std::shared_ptr<zero::async::promise::Promise<std::tuple<int, Target>>>
readRequest(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{5})
            return zero::async::promise::reject<std::tuple<int, Target>>(
                    {-1, "unsupported version"}
            );

        std::shared_ptr<zero::async::promise::Promise<Target>> promise;

        switch (std::to_integer<int>(data[3])) {
            case 1:
                promise = buffer->readExactly(4)->then([=](const std::vector<std::byte> &data) {
                    return buffer->readExactly(2)->then([ip = data](nonstd::span<const std::byte> data) -> Target {
                        aio::net::IPv4Address address = {};

                        address.port = ntohs(*(uint16_t *) data.data());
                        memcpy(address.ip.data(), ip.data(), 4);

                        return address;
                    });
                });

                break;

            case 3:
                promise = buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                    return buffer->readExactly(std::to_integer<size_t>(data[0]));
                })->then([=](nonstd::span<const std::byte> data) {
                    std::string host = std::string{(const char *) data.data(), data.size()};
                    return buffer->readExactly(2)->then(
                            [host = std::move(host)](nonstd::span<const std::byte> data) -> Target {
                                return HostAddress{ntohs(*(uint16_t *) data.data()), host};
                            }
                    );
                });

                break;

            case 4:
                promise = buffer->readExactly(16)->then([=](const std::vector<std::byte> &data) {
                    return buffer->readExactly(2)->then([ip = data](nonstd::span<const std::byte> data) -> Target {
                        aio::net::IPv6Address address = {};

                        address.port = ntohs(*(uint16_t *) data.data());
                        memcpy(address.ip.data(), ip.data(), 16);

                        return address;
                    });
                });

                break;

            default:
                break;
        }

        if (!promise)
            return zero::async::promise::reject<std::tuple<int, Target>>(
                    {-1, "unsupported address type"}
            );

        return promise->then([=](const Target &address) {
            return std::tuple<int, Target>{std::to_integer<int>(data[1]), address};
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<User>>
readUser(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{1}) {
            auto response = {std::byte{1}, std::byte{1}};
            return buffer->write(response)->then([]() {
                return zero::async::promise::reject<User>({-1, "unsupported auth version"});
            });
        }

        return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
            return buffer->readExactly(std::to_integer<size_t>(data[0]));
        })->then([=](nonstd::span<const std::byte> data) {
            std::string username = {(const char *) data.data(), data.size()};

            return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                return buffer->readExactly(std::to_integer<size_t>(data[0]));
            })->then([=, username = std::move(username)](nonstd::span<const std::byte> data) {
                return User{username, {(const char *) data.data(), data.size()}};
            });
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<void>>
handshake(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer, std::optional<User> user) {
    return buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{5})
            return zero::async::promise::reject<std::vector<std::byte>>({-1, "unsupported version"});

        return buffer->readExactly(std::to_integer<size_t>(data[1]));
    })->then([=](nonstd::span<const std::byte> data) {
        if (!user) {
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
            return readUser(buffer);
        })->then([=](const User &input) {
            if (input.username != user->username || input.password != user->password) {
                auto response = {std::byte{1}, std::byte{1}};
                return buffer->write(response)->then([]() {
                    return zero::async::promise::reject<void>({-1, "auth failed"});
                });
            }

            auto response = {std::byte{1}, std::byte{0}};
            return buffer->write(response);
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<std::vector<aio::net::Address>>> resolve(
        const std::shared_ptr<aio::Context> &context,
        const Target &target
) {
    std::shared_ptr<zero::async::promise::Promise<std::vector<aio::net::Address>>> promise;

    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);

            promise = aio::net::dns::lookupIP(context, address.hostname)->then(
                    [=](nonstd::span<const std::variant<std::array<std::byte, 4>, std::array<std::byte, 16>>> ips) {
                        std::vector<aio::net::Address> addresses;

                        std::transform(
                                ips.begin(),
                                ips.end(),
                                std::back_inserter(addresses),
                                [=](const auto &ip) -> aio::net::Address {
                                    if (ip.index() == 0)
                                        return aio::net::IPv4Address{address.port, std::get<0>(ip)};

                                    return aio::net::IPv6Address{address.port, std::get<1>(ip)};
                                }
                        );

                        return addresses;
                    }
            );

            break;
        }

        case 1: {
            auto address = std::get<aio::net::IPv4Address>(target);

            promise = zero::async::promise::resolve<std::vector<aio::net::Address>>(
                    std::vector<aio::net::Address>{aio::net::IPv4Address{address.port, address.ip}}
            );

            break;
        }

        case 2: {
            auto address = std::get<aio::net::IPv6Address>(target);

            promise = zero::async::promise::resolve<std::vector<aio::net::Address>>(
                    std::vector<aio::net::Address>{aio::net::IPv6Address{address.port, address.ip}}
            );

            break;
        }
    }

    return promise;
}

std::optional<std::tuple<Target, nonstd::span<const std::byte>>>
unpack(nonstd::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        LOG_ERROR("fragmentation is not supported");
        return std::nullopt;
    }

    std::optional<std::tuple<Target, nonstd::span<const std::byte>>> packet;

    switch (std::to_integer<int>(data[3])) {
        case 1: {
            aio::net::IPv4Address address = {};

            address.port = ntohs(*(uint16_t *) (data.data() + 8));
            memcpy(address.ip.data(), data.subspan<4, 4>().data(), 4);

            packet = {address, data.subspan(10)};

            break;
        }

        case 3: {
            auto length = std::to_integer<size_t>(data[4]);

            packet = {
                    HostAddress{
                            ntohs(*(uint16_t *) (data.data() + 5 + length)),
                            {(const char *) data.data() + 5, length}
                    },
                    data.subspan(7 + length)
            };

            break;
        }

        case 4: {
            aio::net::IPv6Address address = {};

            address.port = ntohs(*(uint16_t *) (data.data() + 20));
            memcpy(address.ip.data(), data.subspan<4, 16>().data(), 16);

            packet = {address, data.subspan(22)};

            break;
        }

        default:
            break;
    }

    return packet;
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyUDP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer
) {
    std::optional<aio::net::Address> localAddress = buffer->localAddress();

    if (!localAddress)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    bool isIPv4 = localAddress->index() == 0;
    zero::ptr::RefPtr<aio::net::dgram::Socket> local;

    if (isIPv4)
        local = aio::net::dgram::bind(
                context,
                aio::net::IPv4Address{
                        0,
                        std::get<aio::net::IPv4Address>(*localAddress).ip
                }
        );
    else
        local = aio::net::dgram::bind(
                context,
                aio::net::IPv6Address{
                        0,
                        std::get<aio::net::IPv6Address>(*localAddress).ip
                }
        );

    if (!local)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    std::optional<aio::net::Address> bindAddress = local->localAddress();

    if (!bindAddress)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    std::vector<std::byte> response = {std::byte{5}, std::byte{0}, std::byte{0}};

    if (isIPv4) {
        response.push_back(std::byte{1});

        auto ipv4Address = std::get<aio::net::IPv4Address>(*bindAddress);
        unsigned short bindPort = htons(ipv4Address.port);

        response.insert(response.end(), ipv4Address.ip.begin(), ipv4Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    } else {
        response.push_back(std::byte{4});

        auto ipv6Address = std::get<aio::net::IPv6Address>(*bindAddress);
        unsigned short bindPort = htons(ipv6Address.port);

        response.insert(response.end(), ipv6Address.ip.begin(), ipv6Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    }

    return buffer->write(response)->then([=]() {
        return zero::async::promise::race(
                buffer->waitClosed(),
                local->readFrom(10240)->then([=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                    auto packet = unpack(data);

                    if (!packet)
                        return zero::async::promise::reject<void>({-1, "invalid packet"});

                    return resolve(
                            context,
                            std::get<0>(*packet)
                    )->then([
                                    =,
                                    client = from,
                                    payload = std::vector<std::byte>{
                                            std::get<1>(*packet).begin(),
                                            std::get<1>(*packet).end()
                                    }
                            ](nonstd::span<const aio::net::Address> addresses) {
                        const aio::net::Address &address = addresses.front();

                        zero::ptr::RefPtr<aio::net::dgram::Socket> remote = aio::net::dgram::bind(
                                context,
                                address.index() == 0 ? "0.0.0.0" : "::",
                                0
                        );

                        if (!remote)
                            return zero::async::promise::reject<void>({-1, "bind failed"});

                        return remote->writeTo(payload, address)->then([=]() {
                            return zero::async::promise::all(
                                    zero::async::promise::loop<void>([=](const auto &loop) {
                                        local->readFrom(10240)->then(
                                                [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                                    auto packet = unpack(data);

                                                    if (!packet)
                                                        return zero::async::promise::reject<void>(
                                                                {-1, "invalid packet"}
                                                        );

                                                    return resolve(
                                                            context,
                                                            std::get<0>(*packet)
                                                    )->then([
                                                                    =,
                                                                    payload = std::vector<std::byte>{
                                                                            std::get<1>(*packet).begin(),
                                                                            std::get<1>(*packet).end()
                                                                    }
                                                            ](nonstd::span<const aio::net::Address> addresses) {
                                                        return remote->writeTo(payload, addresses.front());
                                                    });
                                                }
                                        )->then([=]() {
                                            P_CONTINUE(loop);
                                        }, [=](const zero::async::promise::Reason &reason) {
                                            P_BREAK_E(loop, reason);
                                        });
                                    }),
                                    zero::async::promise::loop<void>([=](const auto &loop) {
                                        remote->readFrom(10240)->then(
                                                [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                                    std::vector<std::byte> response = {
                                                            std::byte{0}, std::byte{0},
                                                            std::byte{0}
                                                    };

                                                    if (from.index() == 0) {
                                                        response.push_back(std::byte{1});

                                                        auto ipv4Address = std::get<aio::net::IPv4Address>(from);
                                                        unsigned short port = htons(ipv4Address.port);

                                                        response.insert(
                                                                response.end(),
                                                                ipv4Address.ip.begin(),
                                                                ipv4Address.ip.end()
                                                        );

                                                        response.insert(
                                                                response.end(),
                                                                (const std::byte *) &port,
                                                                (const std::byte *) &port + sizeof(unsigned short)
                                                        );

                                                        response.insert(response.end(), data.begin(), data.end());

                                                        return local->writeTo(response, client);
                                                    }

                                                    response.push_back(std::byte{4});

                                                    auto ipv6Address = std::get<aio::net::IPv6Address>(from);
                                                    unsigned short port = htons(ipv6Address.port);

                                                    response.insert(
                                                            response.end(),
                                                            ipv6Address.ip.begin(),
                                                            ipv6Address.ip.end()
                                                    );

                                                    response.insert(
                                                            response.end(),
                                                            (const std::byte *) &port,
                                                            (const std::byte *) &port + sizeof(unsigned short)
                                                    );

                                                    response.insert(response.end(), data.begin(), data.end());

                                                    return local->writeTo(response, client);
                                                }
                                        )->then([=]() {
                                            P_CONTINUE(loop);
                                        }, [=](const zero::async::promise::Reason &reason) {
                                            P_BREAK_E(loop, reason);
                                        });
                                    })
                            );
                        })->finally([=]() {
                            remote->close();
                        });
                    });
                })
        );
    })->finally([=]() {
        local->close();
    });
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyTCP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local,
        const Target &target
) {
    return resolve(context, target)->then([=](nonstd::span<const aio::net::Address> addresses) {
        return aio::net::stream::connect(
                context,
                addresses
        )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
            auto response = {
                    std::byte{5},
                    std::byte{0},
                    std::byte{0},
                    std::byte{1},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}
            };

            return local->write(response)->then([=] {
                return aio::tunnel(local, remote);
            })->finally([=]() {
                remote->close();
            });
        }, [=](const zero::async::promise::Reason &reason) {
            auto response = {
                    std::byte{5},
                    std::byte{5},
                    std::byte{0},
                    std::byte{1},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}
            };

            return local->write(response)->then([=]() {
                return zero::async::promise::reject<void>(reason);
            });
        });
    });
}

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("ip", "listen ip");
    cmdline.add<unsigned short>("port", "bind port");
    cmdline.addOptional<User>("user", 'u', "user auth(username:password)]");

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
    auto user = cmdline.getOptional<User>("user");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context)
        return -1;

    zero::ptr::RefPtr<aio::net::stream::Listener> listener = aio::net::stream::listen(context, ip, port);

    if (!listener)
        return -1;

    zero::async::promise::loop<void>([=](const auto &loop) {
        listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            handshake(buffer, user)->then([=]() {
                return readRequest(buffer);
            })->then([=](int command, const Target &target) {
                LOG_INFO("proxy request: %d %s", command, stringify(target).c_str());

                std::shared_ptr<zero::async::promise::Promise<void>> promise;

                switch (command) {
                    case 1: {
                        promise = proxyTCP(context, buffer, target);
                        break;
                    }

                    case 3: {
                        promise = proxyUDP(context, buffer);
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
