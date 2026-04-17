DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_traffic_rules   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profiles                WHERE config_id = 30;

DELETE FROM xdp_local_configs WHERE config_id = 30;
DELETE FROM xdp_wan_configs   WHERE config_id = 30;
DELETE FROM xdp_redirect_rules WHERE config_id = 30;
DELETE FROM xdp_configs       WHERE id = 30;

INSERT INTO xdp_configs (id) VALUES (30);

INSERT INTO xdp_local_configs (config_id, ifname, network) VALUES
(30, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(30, 'enp6s0', '192.168.203.2/24');

INSERT INTO xdp_profiles (
    config_id,
    profile_name,
    enabled,
    channel_bonding,
    description
) VALUES
(30, 'wan_enp6s0_single', 1, 1, 'WAN group enp6s0 (single), supports multiple source/destination pairs');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp7s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp6s0', 100
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_redirect_rules (config_id, src_cidr, dst_cidr) VALUES
(30, '192.168.9.0/24', '192.168.182.0/24');

INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.9.0/24', '192.168.182.0/24'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

-- Policy metadata only (match tuples are stored in xdp_profile_crypto_policy_matches)
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    300, p.id, 100, 'encrypt_l2', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    301, p.id, 110, 'encrypt_l3', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    302, p.id, 120, 'encrypt_l4', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'ctr', 128, 12, '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    303, p.id, 130, 'bypass', 'ANY',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, NULL
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

-- overlap test: 304 and 305 match same tuple; top-down should pick 305 (priority=40)
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    304, p.id, 150, 'encrypt_l3', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    305, p.id, 40, 'bypass', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, NULL
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

-- grouped matches: same policy_id appears on multiple rows
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(300, 'Any',            'Any', '10.1.1.0/24',       'Any'),
(300, 'Any',            'Any', '10.1.2.0/24',       'Any'),
(300, 'Any',            'Any', '10.1.1.55/32',      'Any'),
(301, '10.5.10.0/24',   'Any', '!10.4.10.0/24',     'Any'),
(301, '10.5.10.77/32',  'Any', '!10.4.10.0/24',     'Any'),
(302, '10.2.2.0/24',    'Any', '10.3.2.0/24',       'Any'),
(303, '10.1.1.0/24',    'Any', '10.11.0.0/24',      'Any'),
(303, '10.1.2.0/24',    'Any', '10.11.0.0/24',      'Any'),
(303, '10.1.1.99/32',   'Any', '10.11.0.10/32',     'Any'),
(304, '192.168.9.0/24', 'Any', '192.168.182.0/24',  '6009'),
(305, '192.168.9.40/32','Any', '192.168.182.40/32', '6009');