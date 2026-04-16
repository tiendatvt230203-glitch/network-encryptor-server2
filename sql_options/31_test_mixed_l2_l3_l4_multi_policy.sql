DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_traffic_rules   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profiles                WHERE config_id = 31;

DELETE FROM xdp_local_configs WHERE config_id = 31;
DELETE FROM xdp_wan_configs   WHERE config_id = 31;
DELETE FROM xdp_redirect_rules WHERE config_id = 31;
DELETE FROM xdp_configs       WHERE id = 31;


INSERT INTO xdp_configs (id) VALUES (31);


INSERT INTO xdp_local_configs (config_id, ifname, network) VALUES
(31, 'eno2', '192.168.180.0/24');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(31, 'enp4s0', '192.168.11.1/24'),
(31, 'enp5s0', '192.168.131.1/24');

INSERT INTO xdp_profiles (
    config_id,
    profile_name,
    enabled,
    channel_bonding,
    description
) VALUES
(31, 'wan_enp4s0_enp5s0_70_30', 1, 1, 'WAN group enp4s0/enp5s0 (70/30), supports multiple source/destination pairs');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN (VALUES
    ('wan_enp4s0_enp5s0_70_30', 'eno2')
) AS w(profile_name, ifname)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;


INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, w.ifname, w.weight
FROM xdp_profiles p
JOIN (VALUES
    ('wan_enp4s0_enp5s0_70_30', 'enp4s0', 70),
    ('wan_enp4s0_enp5s0_70_30', 'enp5s0', 30)
) AS w(profile_name, ifname, weight)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;


INSERT INTO xdp_redirect_rules (config_id, src_cidr, dst_cidr) VALUES
(31, '192.168.180.0/24', '192.168.10.0/24');

INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.180.0/24', '192.168.10.0/24'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    205,
    p.id,
    100,
    'bypass',
    'UDP',
    'Any',
    'Any',
    'Any',
    '5201',
    'gcm',
    128,
    16,
    NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    206,
    p.id,
    110,
    'encrypt_l2',
    'UDP',
    'Any',
    'Any',
    'Any',
    '5202',
    'gcm',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    207,
    p.id,
    120,
    'encrypt_l3',
    'UDP',
    'Any',
    'Any',
    'Any',
    '5203',
    'gcm',
    128,
    16,
    '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    208,
    p.id,
    130,
    'encrypt_l4',
    'UDP',
    'Any',
    'Any',
    'Any',
    '5204',
    'ctr',
    128,
    16,
    '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    217,
    p.id,
    140,
    'bypass',
    'UDP',
    '192.168.180.20',
    'Any',
    '192.168.10.10',
    '5301',
    'gcm',
    128,
    16,
    NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    218,
    p.id,
    150,
    'encrypt_l2',
    'UDP',
    '192.168.180.0/24',
    'Any',
    '192.168.10.11',
    '5302',
    'gcm',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    219,
    p.id,
    160,
    'encrypt_l3',
    'UDP',
    '192.168.180.33',
    'Any',
    '192.168.10.0/24',
    '5303',
    'gcm',
    128,
    16,
    '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    220,
    p.id,
    170,
    'encrypt_l4',
    'UDP',
    '!192.168.180.0/24',
    'Any',
    '192.168.10.44',
    '5304',
    'ctr',
    128,
    16,
    '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    221,
    p.id,
    180,
    'encrypt_l3',
    'TCP',
    '192.168.180.0/24',
    'Any',
    '192.168.10.0/24',
    '5401',
    'gcm',
    128,
    16,
    '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    222,
    p.id,
    190,
    'encrypt_l4',
    'TCP',
    '!192.168.180.50',
    'Any',
    'Any',
    '5402',
    'ctr',
    128,
    16,
    '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    223,
    p.id,
    200,
    'bypass',
    'ICMP',
    'Any',
    'Any',
    'Any',
    'Any',
    'gcm',
    128,
    16,
    NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    224,
    p.id,
    210,
    'encrypt_l2',
    'ANY',
    '!192.168.180.99',
    'Any',
    '!192.168.10.20',
    'Any',
    'gcm',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    226,
    p.id,
    220,
    'encrypt_l4',
    'ANY',
    '192.168.100.0/24,10.0.1.24',
    'Any',
    '192.168.0.0/24,10.2.4.0/12,192.168.182.2,!192.168.100.11',
    'Any',
    'ctr',
    128,
    16,
    '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

-- === Priority / overlap lab (forward 192.168.10.x -> 192.168.180.x) ===
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    230, p.id, 40, 'encrypt_l3', 'UDP',
    '192.168.10.20/32', 'Any', '192.168.180.20/32', '6005',
    'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    231, p.id, 120, 'encrypt_l3', 'UDP',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6005',
    'gcm', 128, 12, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    232, p.id, 88, 'encrypt_l3', 'UDP',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6006',
    'gcm', 128, 12, 'cccccccccccccccccccccccccccccccc'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    233, p.id, 88, 'encrypt_l3', 'UDP',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6006',
    'gcm', 128, 12, 'dddddddddddddddddddddddddddddddd'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    234, p.id, 10, 'encrypt_l3', 'ANY',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6007',
    'gcm', 128, 12, 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    235, p.id, 200, 'encrypt_l3', 'UDP',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6007',
    'gcm', 128, 12, 'ffffffffffffffffffffffffffffffff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    236, p.id, 15, 'bypass', 'UDP',
    '192.168.10.40/32', 'Any', '192.168.180.40/32', '6009',
    'gcm', 128, 12, NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    237, p.id, 45, 'encrypt_l3', 'UDP',
    '192.168.10.0/24', 'Any', '192.168.180.0/24', '6009',
    'gcm', 128, 12, '0123456789abcdef0123456789abcdef'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';