#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/select.h>
#include <pthread.h>
#include <unistd.h>

#include "config.h"
#include "db_config.h"
#include "forwarder.h"
#include "main_diag.h"

#define NOTIFY_CHANNEL "xdp_start"

struct runtime_state {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon mode (LISTEN %s)\n"
            "  %s -id <ID>       # notify daemon to apply config already stored in DB\n"
            "  %s -check [ID]    # check database config consistency\n"
            "\n"
            "The backend must persist config for <ID> in PostgreSQL first.\n"
            "This process only verifies the row exists and sends pg_notify.\n"
            "\n"
            "Env: DB_* is read from the environment (optionally via /opt/db.env).\n"
            "Required: DB_PASS or PGPASSWORD (or /opt/db.env).\n",
            prog, NOTIFY_CHANNEL, prog, prog);
}

static void load_env_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[ENV] Could not open env file: %s\n", path);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = p;
        char *val = eq + 1;

        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        while (*val == ' ' || *val == '\t') val++;

        size_t len = strlen(val);
        while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r')) {
            val[--len] = '\0';
        }

        if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
            val[len - 1] = '\0';
            val++;
        }

        if (*key && *val) {
            setenv(key, val, 0);
        }
    }

    fclose(f);
}

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static const char *resolve_db_password(void) {
    const char *p = getenv("DB_PASS");
    if (p && *p) return p;
    p = getenv("PGPASSWORD");
    if (p && *p) return p;
    return NULL;
}

static int parse_config_id_arg(const char *s, int *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
    }
    long v = strtol(s, NULL, 10);
    if (v < 0 || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

static int run_db_check(const char *const *keywords, const char *const *values, int only_id) {
    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CHECK] DB connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    char where_buf[64] = {0};
    if (only_id >= 0)
        snprintf(where_buf, sizeof(where_buf), "WHERE c.id = %d", only_id);

    char sql[4096];
    snprintf(sql, sizeof(sql),
             "SELECT c.id, "
             "COUNT(DISTINCT p.id) AS profiles, "
             "COUNT(DISTINCT l.id) AS locals, "
             "COUNT(DISTINCT w.id) AS wans, "
             "COUNT(DISTINCT tr.id) AS traffic_rules, "
             "COUNT(DISTINCT cp.id) AS policies "
             "FROM xdp_configs c "
             "LEFT JOIN xdp_profiles p ON p.config_id = c.id "
             "LEFT JOIN xdp_local_configs l ON l.config_id = c.id "
             "LEFT JOIN xdp_wan_configs w ON w.config_id = c.id "
             "LEFT JOIN xdp_profile_traffic_rules tr ON tr.profile_id = p.id "
             "LEFT JOIN xdp_profile_crypto_policies cp ON cp.profile_id = p.id "
             "%s "
             "GROUP BY c.id "
             "ORDER BY c.id;",
             where_buf);

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] summary query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    int rows = PQntuples(res);
    if (rows == 0) {
        fprintf(stderr, "[CHECK] no config found%s\n", (only_id >= 0) ? " for requested id" : "");
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    fprintf(stdout, "[CHECK] Config summary:\n");
    for (int i = 0; i < rows; i++) {
        fprintf(stdout,
                "  id=%s profiles=%s locals=%s wans=%s traffic_rules=%s policies=%s\n",
                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5));
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT cp.id, COUNT(*) "
             "FROM xdp_profile_crypto_policies cp "
             "JOIN xdp_profiles p ON p.id = cp.profile_id "
             "JOIN xdp_configs c ON c.id = p.config_id "
             "%s "
             "GROUP BY cp.id HAVING COUNT(*) > 1 ORDER BY cp.id;",
             where_buf);
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] duplicate policy-id query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] duplicated policy IDs detected:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  policy_id=%s count=%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
    } else {
        fprintf(stdout, "[CHECK] policy-id uniqueness: OK\n");
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT cp.id, cp.aes_bits, cp.nonce_size "
             "FROM xdp_profile_crypto_policies cp "
             "JOIN xdp_profiles p ON p.id = cp.profile_id "
             "JOIN xdp_configs c ON c.id = p.config_id "
             "%s%s "
             "(cp.aes_bits NOT IN (128,256) OR cp.nonce_size < 4 OR cp.nonce_size > 16) "
             "ORDER BY cp.id;",
             where_buf,
             (where_buf[0] == '\0') ? "WHERE " : " AND ");
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] policy-params query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] invalid policy params detected:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  policy_id=%s aes_bits=%s nonce_size=%s\n",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2));
    } else {
        fprintf(stdout, "[CHECK] policy params (aes_bits/nonce_size): OK\n");
    }
    PQclear(res);
    PQfinish(conn);
    return 0;
}

static int find_local_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int find_wan_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int append_local_unique(struct app_config *dst, const struct local_config *src_loc) {
    int idx = find_local_by_ifname(dst, src_loc->ifname);
    if (idx >= 0)
        return idx;
    if (dst->local_count >= MAX_INTERFACES)
        return -1;
    dst->locals[dst->local_count] = *src_loc;
    return dst->local_count++;
}

static int append_wan_unique(struct app_config *dst, const struct wan_config *src_wan) {
    int idx = find_wan_by_ifname(dst, src_wan->ifname);
    if (idx >= 0)
        return idx;
    if (dst->wan_count >= MAX_INTERFACES)
        return -1;
    dst->wans[dst->wan_count] = *src_wan;
    return dst->wan_count++;
}

static int append_policy_unique(struct app_config *dst, const struct crypto_policy *src_cp) {
    for (int i = 0; i < dst->policy_count; i++) {
        if (dst->policies[i].id == src_cp->id)
            return i;
    }
    if (dst->policy_count >= MAX_CRYPTO_POLICIES)
        return -1;
    dst->policies[dst->policy_count] = *src_cp;
    return dst->policy_count++;
}

static void append_redirect_unique(struct app_config *dst, const struct app_config *src) {
    for (uint32_t i = 0; i < src->redirect.src_count; i++) {
        int exists = 0;
        for (uint32_t j = 0; j < dst->redirect.src_count; j++) {
            if (dst->redirect.src_net[j] == src->redirect.src_net[i] &&
                dst->redirect.src_mask[j] == src->redirect.src_mask[i]) {
                exists = 1;
                break;
            }
        }
        if (!exists && dst->redirect.src_count < MAX_SRC_NETS) {
            uint32_t k = dst->redirect.src_count++;
            dst->redirect.src_net[k] = src->redirect.src_net[i];
            dst->redirect.src_mask[k] = src->redirect.src_mask[i];
        }
    }
    for (uint32_t i = 0; i < src->redirect.dst_count; i++) {
        int exists = 0;
        for (uint32_t j = 0; j < dst->redirect.dst_count; j++) {
            if (dst->redirect.dst_net[j] == src->redirect.dst_net[i] &&
                dst->redirect.dst_mask[j] == src->redirect.dst_mask[i]) {
                exists = 1;
                break;
            }
        }
        if (!exists && dst->redirect.dst_count < MAX_DST_NETS) {
            uint32_t k = dst->redirect.dst_count++;
            dst->redirect.dst_net[k] = src->redirect.dst_net[i];
            dst->redirect.dst_mask[k] = src->redirect.dst_mask[i];
        }
    }
}

static int merge_one_config(struct app_config *dst, const struct app_config *src) {
    int local_map[MAX_INTERFACES];
    int wan_map[MAX_INTERFACES];
    int policy_map[MAX_CRYPTO_POLICIES];
    memset(local_map, -1, sizeof(local_map));
    memset(wan_map, -1, sizeof(wan_map));
    memset(policy_map, -1, sizeof(policy_map));

    for (int i = 0; i < src->local_count; i++) {
        local_map[i] = append_local_unique(dst, &src->locals[i]);
        if (local_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->wan_count; i++) {
        wan_map[i] = append_wan_unique(dst, &src->wans[i]);
        if (wan_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->policy_count; i++) {
        policy_map[i] = append_policy_unique(dst, &src->policies[i]);
        if (policy_map[i] < 0)
            return -1;
    }

    append_redirect_unique(dst, src);

    for (int pi = 0; pi < src->profile_count; pi++) {
        if (dst->profile_count >= MAX_PROFILES)
            return -1;
        struct profile_config *dp = &dst->profiles[dst->profile_count++];
        const struct profile_config *sp = &src->profiles[pi];
        memset(dp, 0, sizeof(*dp));
        dp->id = sp->id;
        strncpy(dp->name, sp->name, sizeof(dp->name) - 1);
        dp->enabled = sp->enabled;
        dp->channel_bonding = sp->channel_bonding;

        for (int i = 0; i < sp->local_count; i++) {
            int sli = sp->local_indices[i];
            if (sli < 0 || sli >= src->local_count)
                continue;
            if (dp->local_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->local_indices[dp->local_count++] = local_map[sli];
        }
        for (int i = 0; i < sp->wan_count; i++) {
            int swi = sp->wan_indices[i];
            if (swi < 0 || swi >= src->wan_count)
                continue;
            if (dp->wan_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->wan_indices[dp->wan_count] = wan_map[swi];
            dp->wan_bandwidth_weight[dp->wan_count] = sp->wan_bandwidth_weight[i];
            dp->wan_count++;
        }
        for (int i = 0; i < sp->traffic_rule_count && i < MAX_PROFILE_TRAFFIC_RULES; i++) {
            dp->traffic_rules[i] = sp->traffic_rules[i];
            dp->traffic_rule_count++;
        }
        for (int i = 0; i < sp->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
            int spi = sp->policy_indices[i];
            if (spi < 0 || spi >= src->policy_count)
                continue;
            if (dp->policy_count >= MAX_CRYPTO_POLICIES)
                break;
            dp->policy_indices[dp->policy_count++] = policy_map[spi];
        }
    }
    return 0;
}

static int build_merged_config(struct app_config *out_cfg, const int *ids, int id_count, const char *db_pass) {
    struct app_config merged;
    memset(&merged, 0, sizeof(merged));
    strncpy(merged.bpf_file, "bpf/xdp_redirect.o", sizeof(merged.bpf_file) - 1);
    merged.global_frame_size = DEFAULT_FRAME_SIZE;
    merged.global_batch_size = DEFAULT_BATCH_SIZE;

    for (int i = 0; i < id_count; i++) {
        struct app_config tmp;
        if (config_load_from_db(&tmp, ids[i], db_pass) != 0)
            return -1;
        if (merge_one_config(&merged, &tmp) != 0)
            return -1;
    }

    merged.crypto_enabled = (merged.policy_count > 0) ? 1 : 0;
    if (merged.crypto_enabled) {
        merged.encrypt_layer = 3;
        merged.fake_protocol = 99;
        merged.fake_ethertype_ipv4 = 0x88b5;
        merged.fake_ethertype_ipv6 = 0x88b6;
        merged.crypto_mode = merged.policies[0].crypto_mode;
        merged.aes_bits = merged.policies[0].aes_bits;
        merged.nonce_size = merged.policies[0].nonce_size;
        memcpy(merged.crypto_key, merged.policies[0].key, sizeof(merged.crypto_key));
    }

    if (config_validate(&merged) != 0)
        return -1;
    *out_cfg = merged;
    return 0;
}

static void *forwarder_thread_main(void *arg) {
    struct runtime_state *rt = (struct runtime_state *)arg;
    if (forwarder_init(&rt->fwd, &rt->cfg) != 0) {
        fprintf(stderr, "[FATAL] forwarder_init failed for merged active configs\n");
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    forwarder_cleanup(&rt->fwd);
    rt->running = 0;
    return NULL;
}

static void runtime_stop(struct runtime_state *rt) {
    if (!rt->has_thread)
        return;
    if (rt->running)
        forwarder_stop();
    pthread_join(rt->thread, NULL);
    rt->has_thread = 0;
    rt->running = 0;
}

static int runtime_start(struct runtime_state *rt, const struct app_config *cfg) {
    rt->cfg = *cfg;
    rt->running = 0;
    if (pthread_create(&rt->thread, NULL, forwarder_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

int main(int argc, char **argv) {
    load_env_from_file("/opt/db.env");

    const char *db_pass = resolve_db_password();
    const char *keywords[] = {"host", "port", "dbname", "user", "password", "connect_timeout", NULL};
    const char *values[]   = {getenv("DB_HOST"), getenv("DB_PORT"), getenv("DB_NAME"),
                              getenv("DB_USER"), db_pass, "10", NULL};

    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    int config_id = -1;
    int check_mode = 0;
    int check_id = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            if (parse_config_id_arg(argv[++i], &config_id) != 0) {
                fprintf(stderr, "[FATAL] config_id must be a number (digits only)\n");
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-check") == 0) {
            check_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (parse_config_id_arg(argv[++i], &check_id) != 0) {
                    fprintf(stderr, "[FATAL] check id must be a number (digits only)\n");
                    usage(argv[0]);
                    return 1;
                }
            }
        }
    }

    if (check_mode) {
        if (!db_pass || !*db_pass) {
            fprintf(stderr,
                    "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or provide /opt/db.env).\n");
            return 1;
        }
        return run_db_check(keywords, values, check_id);
    }

    if (config_id >= 0) {
        if (!db_pass || !*db_pass) {
            fprintf(stderr,
                    "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or provide /opt/db.env).\n");
            return 1;
        }

        PGconn *conn = PQconnectdbParams(keywords, values, 0);
        if (PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(conn));
            PQfinish(conn);
            return 1;
        }

        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d", config_id);
        const char *check_params[1] = { id_str };
        PGresult *check_res = PQexecParams(
            conn,
            "SELECT 1 FROM xdp_configs WHERE id = $1::int",
            1,
            NULL,
            check_params,
            NULL,
            NULL,
            0);
        if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "[FATAL] config id lookup failed: %s", PQerrorMessage(conn));
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }
        if (PQntuples(check_res) == 0) {
            fprintf(stderr, "[FATAL] config_id=%d not found in xdp_configs (backend must insert it first)\n",
                    config_id);
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }
        PQclear(check_res);

        const char *notifyParams[2] = { NOTIFY_CHANNEL, id_str };
        PGresult *notify_res = PQexecParams(
            conn,
            "SELECT pg_notify($1, $2);",
            2,
            NULL,
            notifyParams,
            NULL,
            NULL,
            0);
        ExecStatusType st = PQresultStatus(notify_res);
        if (!(st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK)) {
            fprintf(stderr, "[FATAL] pg_notify failed: %s", PQerrorMessage(conn));
            if (notify_res) PQclear(notify_res);
            PQfinish(conn);
            return 1;
        }
        if (notify_res) PQclear(notify_res);
        PQfinish(conn);

        fprintf(stderr, "[OK] Notified %s with config_id=%d\n", NOTIFY_CHANNEL, config_id);
        return 0;
    }

    if (!db_pass || !*db_pass) {
        fprintf(stderr,
                "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or /opt/db.env)\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_silent);
    PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    struct runtime_state rt;
    memset(&rt, 0, sizeof(rt));
    int active_ids[32];
    int active_id_count = 0;

    for (;;) {
        int pq_fd = PQsocket(listen_conn);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0)
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = atoi(notify->extra);
            int exists = 0;
            for (int i = 0; i < active_id_count; i++) {
                if (active_ids[i] == id) {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                if (active_id_count >= (int)(sizeof(active_ids) / sizeof(active_ids[0]))) {
                    fprintf(stderr, "[WARN] active config set is full, ignoring id=%d\n", id);
                    PQfreemem(notify);
                    continue;
                }
                active_ids[active_id_count++] = id;
            }

            struct app_config merged_cfg;
            if (build_merged_config(&merged_cfg, active_ids, active_id_count, db_pass) == 0) {
                main_diag_log_loaded_config(&merged_cfg, id);
                runtime_stop(&rt);
                if (runtime_start(&rt, &merged_cfg) != 0) {
                    fprintf(stderr, "[FATAL] failed to start merged runtime\n");
                } else {
                    fprintf(stderr, "[OK] Applied merged runtime with %d active config(s)\n", active_id_count);
                }
            } else {
                fprintf(stderr, "[FATAL] failed to build merged config set after notify id=%d\n", id);
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }
}