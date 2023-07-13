#include <aio/net/stream.h>
#include <aio/net/dgram.h>
#include <aio/net/dns.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/net.h>

#ifdef __unix__
#include <csignal>
#endif

enum Error {
    INVALID_VERSION = -2000,
    INVALID_ADDRESS,
    INVALID_REQUEST,
    INVALID_USER,
    INVALID_PACKET,
    UNSUPPORTED_METHOD,
    UNSUPPORTED_AUTH_METHOD,
    HANDSHAKE_FAILED,
    ADDRESS_RESOLVE_ERROR,
    AUTH_FAILED,
    PROXY_FAILED
};

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
            result = aio::net::stringify(std::get<aio::net::IPv4Address>(target));
            break;
        }

        case 2: {
            result = aio::net::stringify(std::get<aio::net::IPv6Address>(target));
            break;
        }
    }

    return result;
}

bool matchSource(const aio::net::Address &source, const aio::net::Address &from) {
    if (source.index() != from.index())
        return false;

    if (source.index() == 0) {
        auto sourceAddress = std::get<aio::net::IPv4Address>(source);
        auto fromAddress = std::get<aio::net::IPv4Address>(from);

        if (sourceAddress.port != 0 && sourceAddress.port != fromAddress.port)
            return false;

        if (std::all_of(
                sourceAddress.ip.begin(),
                sourceAddress.ip.end(),
                [](const auto &byte) {
                    return byte == std::byte{0};
                }
        ))
            return true;

        return std::equal(sourceAddress.ip.begin(), sourceAddress.ip.end(), fromAddress.ip.begin());
    }

    auto sourceAddress = std::get<aio::net::IPv6Address>(source);
    auto fromAddress = std::get<aio::net::IPv6Address>(from);

    if (sourceAddress.port != 0 && sourceAddress.port != fromAddress.port)
        return false;

    if (std::all_of(
            sourceAddress.ip.begin(),
            sourceAddress.ip.end(),
            [](const auto &byte) {
                return byte == std::byte{0};
            }
    ))
        return true;

    return std::equal(sourceAddress.ip.begin(), sourceAddress.ip.end(), fromAddress.ip.begin());
}

std::shared_ptr<zero::async::promise::Promise<std::tuple<int, Target>>>
readRequest(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
        int version = std::to_integer<int>(data[0]);

        if (version != 5)
            return zero::async::promise::reject<std::tuple<int, Target>>(
                    {INVALID_VERSION, zero::strings::format("unsupported socks version[%d]", version)}
            );

        int type = std::to_integer<int>(data[3]);
        std::shared_ptr<zero::async::promise::Promise<Target>> promise;

        switch (type) {
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
                    {INVALID_ADDRESS, zero::strings::format("unsupported address type[%d]", type)}
            );

        return promise->then([=](const Target &address) {
            return std::tuple<int, Target>{std::to_integer<int>(data[1]), address};
        });
    })->fail(PF_RETHROW(INVALID_REQUEST, "read proxy request failed"));
}

std::shared_ptr<zero::async::promise::Promise<User>>
readUser(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
        int version = std::to_integer<int>(data[0]);

        if (version != 1) {
            auto response = {std::byte{1}, std::byte{1}};
            return buffer->write(response)->then([=]() {
                return zero::async::promise::reject<User>(
                        {INVALID_VERSION, zero::strings::format("unsupported auth version[%d]", version)}
                );
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
    })->fail(PF_RETHROW(INVALID_USER, "read user failed"));
}

std::shared_ptr<zero::async::promise::Promise<void>>
handshake(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer, std::optional<User> user) {
    return buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
        int version = std::to_integer<int>(data[0]);

        if (version != 5)
            return zero::async::promise::reject<std::vector<std::byte>>(
                    {INVALID_VERSION, zero::strings::format("unsupported socks version[%d]", version)}
            );

        return buffer->readExactly(std::to_integer<size_t>(data[1]));
    })->then([=](nonstd::span<const std::byte> data) {
        if (!user) {
            auto response = {std::byte{5}, std::byte{0}};
            return buffer->write(response);
        }

        if (std::find(data.begin(), data.end(), std::byte{2}) == data.end()) {
            auto response = {std::byte{5}, std::byte{0xff}};
            return buffer->write(response)->then([]() {
                return zero::async::promise::reject<void>({UNSUPPORTED_AUTH_METHOD, "unsupported auth method"});
            });
        }

        auto response = {std::byte{5}, std::byte{2}};

        return buffer->write(response)->then([=]() {
            return readUser(buffer);
        })->then([=](const User &input) {
            if (input.username != user->username || input.password != user->password) {
                auto response = {std::byte{1}, std::byte{1}};
                return buffer->write(response)->then([]() {
                    return zero::async::promise::Reason{AUTH_FAILED, "auth failed"};
                });
            }

            auto response = {std::byte{1}, std::byte{0}};
            return buffer->write(response);
        });
    })->fail(PF_RETHROW(HANDSHAKE_FAILED, "handshake failed"));
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

    return promise->fail(
            PF_RETHROW(
                    ADDRESS_RESOLVE_ERROR,
                    zero::strings::format("resolve target %s failed", stringify(target).c_str())
            )
    );
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
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer,
        const std::optional<aio::net::Address> &source
) {
    std::optional<aio::net::Address> localAddress = buffer->localAddress();

    if (!localAddress)
        return zero::async::promise::reject<void>(
                {aio::IO_ERROR, zero::strings::format("failed to get local address[%s]", aio::lastError().c_str())}
        );

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
        return zero::async::promise::reject<void>(
                {
                        aio::IO_ERROR,
                        zero::strings::format("bind datagram socket failed[%s]", aio::lastError().c_str())
                }
        );

    std::optional<aio::net::Address> bindAddress = local->localAddress();

    if (!bindAddress)
        return zero::async::promise::reject<void>(
                {aio::IO_ERROR, zero::strings::format("failed to get local address[%s]", aio::lastError().c_str())}
        );

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
                zero::async::promise::loop<std::pair<aio::net::Address, zero::ptr::RefPtr<aio::net::dgram::Socket>>>(
                        [=](const auto &loop) {
                            local->readFrom(10240)->then(
                                    [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                        if (source && !matchSource(*source, from)) {
                                            LOG_WARNING(
                                                    "forbidden address: %s does not match %s",
                                                    stringify(from).c_str(),
                                                    stringify(*source).c_str()
                                            );

                                            P_CONTINUE(loop);
                                            return;
                                        }

                                        LOG_INFO("UDP client: %s", stringify(from).c_str());

                                        auto packet = unpack(data);

                                        if (!packet) {
                                            P_BREAK_E(loop, { INVALID_PACKET, "invalid UDP packet" });
                                            return;
                                        }

                                        const auto &[target, payload] = *packet;

                                        resolve(
                                                context,
                                                target
                                        )->then([
                                                        =,
                                                        target = target,
                                                        payload = std::vector<std::byte>{payload.begin(), payload.end()}
                                                ](nonstd::span<const aio::net::Address> addresses) {
                                            LOG_DEBUG(
                                                    "UDP packet[%zu]: %s ==> %s",
                                                    payload.size(),
                                                    stringify(from).c_str(),
                                                    stringify(target).c_str()
                                            );

                                            const aio::net::Address &address = addresses.front();

                                            zero::ptr::RefPtr<aio::net::dgram::Socket> remote = aio::net::dgram::bind(
                                                    context,
                                                    address.index() == 0 ? "0.0.0.0" : "::",
                                                    0
                                            );

                                            if (!remote)
                                                return zero::async::promise::reject<void>({-1, "bind failed"});

                                            return remote->writeTo(payload, address)->then([=]() {
                                                P_BREAK_V(loop, std::pair{from, remote});
                                            })->fail([=](const zero::async::promise::Reason &reason) {
                                                remote->close();
                                                return reason;
                                            });
                                        })->fail(PF_LOOP_THROW(loop));
                                    });
                        }
                )->then([=](const aio::net::Address &client, const zero::ptr::RefPtr<aio::net::dgram::Socket> &remote) {
                    return zero::async::promise::all(
                            zero::async::promise::doWhile([=]() {
                                return local->readFrom(10240)->then(
                                        [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                            auto packet = unpack(data);

                                            if (!packet)
                                                return zero::async::promise::reject<void>(
                                                        {-1, "invalid packet"}
                                                );

                                            const auto &[target, payload] = *packet;

                                            return resolve(
                                                    context,
                                                    target
                                            )->then([
                                                            =,
                                                            target = target,
                                                            payload = std::vector<std::byte>{
                                                                    payload.begin(),
                                                                    payload.end()
                                                            }
                                                    ](nonstd::span<const aio::net::Address> addresses) {
                                                LOG_DEBUG(
                                                        "UDP packet[%zu]: %s ==> %s",
                                                        payload.size(),
                                                        stringify(client).c_str(),
                                                        stringify(target).c_str()
                                                );

                                                return remote->writeTo(payload, addresses.front());
                                            });
                                        }
                                );
                            }),
                            zero::async::promise::doWhile([=]() {
                                return remote->readFrom(10240)->then(
                                        [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                            LOG_DEBUG(
                                                    "UDP packet[%zu]: %s <== %s",
                                                    data.size(),
                                                    stringify(client).c_str(),
                                                    stringify(from).c_str()
                                            );

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
                                );
                            })
                    )->finally([=]() {
                        LOG_INFO("UDP proxy finished: client[%s]", stringify(client).c_str());
                        remote->close();
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
    std::optional<aio::net::Address> clientAddress = local->remoteAddress();

    if (!clientAddress)
        return zero::async::promise::reject<void>(
                {aio::IO_ERROR, zero::strings::format("failed to get remote address[%s]", aio::lastError().c_str())}
        );

    LOG_INFO(
            "TCP proxy request: client[%s] target[%s]",
            stringify(*clientAddress).c_str(),
            stringify(target).c_str()
    );

    return resolve(context, target)->then([=](nonstd::span<const aio::net::Address> addresses) {
        return aio::net::stream::connect(
                context,
                addresses
        )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
            LOG_INFO(
                    "TCP tunnel: client[%s] target[%s]",
                    stringify(*clientAddress).c_str(),
                    stringify(target).c_str()
            );

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
                return reason;
            });
        });
    })->finally([=]() {
        LOG_INFO("TCP proxy finished: client[%s]", stringify(*clientAddress).c_str());
    });
}

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("ip", "listen ip");
    cmdline.add<unsigned short>("port", "bind port");
    cmdline.addOptional<User>("user", 'u', "user auth(username:password)]");
    cmdline.addOptional("strict", '\0', "restrict UDP source addresses");

    cmdline.parse(argc, argv);

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return -1;
    }
#endif

#ifdef __unix__
    signal(SIGPIPE, SIG_IGN);
#endif

    auto ip = cmdline.get<std::string>("ip");
    auto port = cmdline.get<unsigned short>("port");
    auto user = cmdline.getOptional<User>("user");
    auto strict = cmdline.exist("strict");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context)
        return -1;

    zero::ptr::RefPtr<aio::net::stream::Listener> listener = aio::net::stream::listen(context, ip, port);

    if (!listener)
        return -1;

    zero::async::promise::doWhile([=]() {
        return listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            handshake(buffer, user)->then([=]() {
                return readRequest(buffer);
            })->then([=](int command, const Target &target) {
                std::shared_ptr<zero::async::promise::Promise<void>> promise;

                switch (command) {
                    case 1: {
                        promise = proxyTCP(context, buffer, target);
                        break;
                    }

                    case 3: {
                        std::optional<aio::net::Address> source;

                        if (strict) {
                            switch (target.index()) {
                                case 1:
                                    source = std::get<aio::net::IPv4Address>(target);
                                    break;

                                case 2:
                                    source = std::get<aio::net::IPv6Address>(target);
                                    break;

                                default:
                                    break;
                            }
                        }

                        promise = proxyUDP(context, buffer, source);
                        break;
                    }

                    default:
                        break;
                }

                if (!promise)
                    return zero::async::promise::reject<void>(
                            {UNSUPPORTED_METHOD, zero::strings::format("unsupported proxy command[%d]", command)}
                    );

                return promise;
            })->fail([](const zero::async::promise::Reason &reason) {
                std::vector<std::string> messages = {
                        zero::strings::format("code[%d] msg[%s]", reason.code, reason.message.c_str())
                };

                for (auto p = reason.previous; p; p = p->previous)
                    messages.push_back(zero::strings::format("code[%d] msg[%s]", p->code, p->message.c_str()));

                LOG_ERROR(
                        "%s",
                        zero::strings::join(messages, " << ").c_str()
                );
            })->finally([=]() {
                buffer->close();
            });
        });
    })->fail([](const zero::async::promise::Reason &reason) {
        LOG_ERROR("code[%d] msg[%s]", reason.code, reason.message.c_str());
    })->finally([=]() {
        context->loopBreak();
    });

    context->dispatch();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
