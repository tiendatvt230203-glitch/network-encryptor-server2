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
(31, 'profile_180_to_10', 1, 1, '192.168.180.0/24 <-> 192.168.10.0/24 via enp4s0,enp5s0');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN (VALUES
    ('profile_180_to_10', 'eno2')
) AS w(profile_name, ifname)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;


INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, w.ifname, w.weight
FROM xdp_profiles p
JOIN (VALUES
    ('profile_180_to_10', 'enp4s0', 70),
    ('profile_180_to_10', 'enp5s0', 30)
) AS w(profile_name, ifname, weight)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;


INSERT INTO xdp_redirect_rules (config_id, src_cidr, dst_cidr) VALUES
(31, '192.168.180.0/24', '192.168.10.0/24');

INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.180.0/24', '192.168.10.0/24'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

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
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

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
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

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
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

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
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';