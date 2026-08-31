/**
 * @file tests/unit/test_network.cpp
 * @brief Test src/network.*
 */
#include "../tests_common.h"

#include <src/network.h>

struct MdnsInstanceNameTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(MdnsInstanceNameTest, Run) {
  auto [input, expected] = GetParam();
  ASSERT_EQ(net::mdns_instance_name(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  MdnsInstanceNameTests,
  MdnsInstanceNameTest,
  testing::Values(
    std::make_tuple("shortname-123", "shortname-123"),
    std::make_tuple("space 123", "space-123"),
    std::make_tuple("hostname.domain.test", "hostname"),
    std::make_tuple("&", "Sunshine"),
    std::make_tuple("", "Sunshine"),
    std::make_tuple("😁", "Sunshine"),
    std::make_tuple(std::string(128, 'a'), std::string(63, 'a'))
  )
);

struct NetworkScopeTest: BaseTest,
                         testing::WithParamInterface<std::tuple<std::string, net::net_e>> {};

TEST_P(NetworkScopeTest, ClassifiesRemotePeerAddress) {
  const auto &[address, expected] = GetParam();
  EXPECT_EQ(net::from_address(address), expected);
}

INSTANTIATE_TEST_SUITE_P(
  StationConnectNetworkScopes,
  NetworkScopeTest,
  testing::Values(
    std::make_tuple("127.0.0.1", net::net_e::PC),
    std::make_tuple("::1", net::net_e::PC),
    std::make_tuple("10.23.42.10", net::net_e::LAN),
    std::make_tuple("172.31.255.254", net::net_e::LAN),
    std::make_tuple("192.168.42.250", net::net_e::LAN),
    std::make_tuple("100.64.0.1", net::net_e::LAN),
    std::make_tuple("169.254.1.1", net::net_e::LAN),
    std::make_tuple("fc00::1", net::net_e::LAN),
    std::make_tuple("fe80::1", net::net_e::LAN),
    std::make_tuple("8.8.8.8", net::net_e::WAN),
    std::make_tuple("2001:4860:4860::8888", net::net_e::WAN)
  )
);
