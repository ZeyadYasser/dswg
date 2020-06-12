package dswg

func setupDB() DB {
	db, _ := OpenSqliteDB(":memory:")
	return db
}

func baseLink() Link {
	addr1, _ := ParseIPNet("10.6.6.1/24")
	addr2, _ := ParseIPNet("10.6.6.2/24")
	ipv4, _ := ParseIPNet("10.6.6.1/24")
	ipv6, _ := ParseIPNet("2001:0000::/32")
	dns1, _ := ParseIP("1.1.1.1")
	key, _ := ParseKey("4AQ6d+dvykkl4j6VG03e7VcciDbgn5mBEJFXMjn1pnU=")
	return Link{
		Name: "wg-linko",
		MTU: 1420,
		Enable: true,
		PrivateKey: *key,
		ListenPort: 9977,
		FirewallMark: 42069,
		AddressIPv4: ipv4,
		AddressIPv6: ipv6,
		DefaultDNS1: dns1,
		PostDown: []string{"cmd1", "cmd2"},
		PostUp: []string{"cmd3"},
		DefaultAllowedIPs: []IPNet{*addr1, *addr2},
		Forward: false,
	}
}

func basePeer() Peer {
	addr1, _ := ParseIPNet("10.9.6.2/32")
	addr2, _ := ParseIPNet("10.9.6.10/32")
	key, _ := ParseKey("ZOZ+ngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	dns1, _ := ParseIP("1.1.1.1")
	endpoint, _ := ParseUDP("192.168.0.1:42064")
	return Peer{
		Name: "zoz-pc",
		Enable: false,
		PublicKey: *key,
		Endpoint: endpoint,
		DNS1: dns1,
		AllowedIPs: []IPNet{*addr1, *addr2},
	}
}

func baseClient() Client {
	client, _ := NewClient(setupDB())
	return *client
}
