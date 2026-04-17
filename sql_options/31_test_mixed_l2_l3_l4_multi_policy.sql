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
(31, 'eno2', '192.168.10.0/24');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(31, 'enp4s0', '192.168.11.2/24'),
(31, 'enp5s0', '192.168.131.2/24');

INSERT INTO xdp_profiles (
    config_id,
    profile_name,
    enabled,
    channel_bonding,
    description
) VALUES
(31, 'wan_enp4s0_enp5s0_70_30', 1, 1, 'WAN group enp4s0/enp5s0 (70/30), supports multiple source/destination pairs');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'eno2'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';


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
(31, '192.168.10.0/24', '192.168.180.0/24');

INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.10.0/24', '192.168.180.0/24'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

-- Policy metadata only (match tuples are stored in xdp_profile_crypto_policy_matches)
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    400, p.id, 100, 'encrypt_l2', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    401, p.id, 110, 'encrypt_l3', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    402, p.id, 120, 'encrypt_l4', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'ctr', 128, 12, '00112233445566778899aabbccddeeff'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    403, p.id, 130, 'bypass', 'ANY',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

-- overlap test: 404 and 405 match same tuple; top-down should pick 405 (priority=40)
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    404, p.id, 150, 'encrypt_l3', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    405, p.id, 40, 'bypass', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 12, NULL
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

-- grouped matches: same policy_id appears on multiple rows
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(400, 'Any',              'Any', '10.1.1.0/24',       'Any'),
(400, 'Any',              'Any', '10.1.2.0/24',       'Any'),
(400, 'Any',              'Any', '10.1.2.55/32',      'Any'),
(401, '10.5.10.0/24',     'Any', '!10.4.10.0/24',     'Any'),
(401, '10.5.10.77/32',    'Any', '!10.4.10.0/24',     'Any'),
(402, '10.2.2.0/24',      'Any', '10.3.2.0/24',       'Any'),
(403, '10.1.1.0/24',      'Any', '10.11.0.0/24',      'Any'),
(403, '10.1.2.0/24',      'Any', '10.11.0.0/24',      'Any'),
(403, '10.1.2.99/32',     'Any', '10.11.0.10/32',     'Any'),
(404, '192.168.10.0/24',  'Any', '192.168.180.0/24',  '6009'),
(405, '192.168.10.40/32', 'Any', '192.168.180.40/32', '6009');