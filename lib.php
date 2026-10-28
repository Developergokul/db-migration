<?php
declare(strict_types=1);

/**
 * DB Migrator – shared library (config, security, job store, transfer engine).
 */

if (is_file(__DIR__ . '/config.local.php')) {
    require __DIR__ . '/config.local.php';
}
defined('DATA_DIR')      || define('DATA_DIR', getenv('MIGRATOR_DATA_DIR') ?: __DIR__ . '/data');
defined('ALLOWED_IPS')   || define('ALLOWED_IPS', ['127.0.0.1', '::1']);
defined('STEP_SECONDS')  || define('STEP_SECONDS', 20);          // max seconds of work per HTTP request
defined('BATCH_BYTES')   || define('BATCH_BYTES', 2 * 1024 * 1024); // target payload per batch
defined('MAX_BATCH_ROWS') || define('MAX_BATCH_ROWS', 5000);

if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0700, true);
}

/* ------------------------------------------------------------------ */
/* Credential vault: AES-256-GCM, key kept in DATA_DIR/.key            */
/* ------------------------------------------------------------------ */
final class Vault
{
    private static function key(): string
    {
        $f = DATA_DIR . '/.key';
        if (!is_file($f)) {
            $h = @fopen($f, 'xb');
            if ($h) {
                fwrite($h, random_bytes(32));
                fclose($h);
                @chmod($f, 0600);
            }
        }
        $k = (string)file_get_contents($f);
        if (strlen($k) !== 32) {
            throw new RuntimeException('Encryption key missing or corrupt: ' . $f);
        }
        return $k;
    }

    public static function encrypt(string $plain): string
    {
        $iv  = random_bytes(12);
        $tag = '';
        $ct  = openssl_encrypt($plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $blob): ?string
    {
        $raw = base64_decode($blob, true);
        if ($raw === false || strlen($raw) < 29) {
            return null;
        }
        $p = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
        return $p === false ? null : $p;
    }
}

final class Config
{
    private static function path(): string { return DATA_DIR . '/config.enc'; }

    public static function defaults(): array
    {
        return [
            'local'  => ['host' => '127.0.0.1', 'port' => 3306, 'user' => 'root', 'pass' => '', 'db' => ''],
            'remote' => ['host' => '', 'port' => 3306, 'user' => '', 'pass' => '', 'db' => '', 'ssl' => 0, 'ssl_verify' => 0, 'ca' => ''],
        ];
    }

    public static function load(): array
    {
        $d = self::defaults();
        if (is_file(self::path())) {
            $plain = Vault::decrypt((string)file_get_contents(self::path()));
            $c = $plain ? json_decode($plain, true) : null;
            if (is_array($c)) {
                foreach (['local', 'remote'] as $k) {
                    $d[$k] = array_merge($d[$k], $c[$k] ?? []);
                }
            }
        }
        return $d;
    }

    public static function save(array $c): void
    {
        file_put_contents(self::path(), Vault::encrypt(json_encode($c)), LOCK_EX);
        @chmod(self::path(), 0600);
    }

    /** Config safe to send to the browser: passwords never leave the server. */
    public static function masked(array $c): array
    {
        foreach (['local', 'remote'] as $k) {
            $c[$k]['has_pass'] = ($c[$k]['pass'] ?? '') !== '';
            unset($c[$k]['pass']);
        }
        return $c;
    }

    /** Merge posted form values over stored ones; empty password = keep stored. Validates input. */
    public static function merge(array $stored, array $post): array
    {
        foreach (['local', 'remote'] as $k) {
            $p = $post[$k] ?? [];
            $s = &$stored[$k];
            $host = trim((string)($p['host'] ?? $s['host']));
            $db   = trim((string)($p['db'] ?? $s['db']));
            if ($host !== '' && !preg_match('/^[A-Za-z0-9._:\-\[\]]+$/', $host)) {
                throw new InvalidArgumentException("Invalid $k host");
            }
            if ($db !== '' && !preg_match('/^[^;`\x00]+$/', $db)) {
                throw new InvalidArgumentException("Invalid $k database name");
            }
            $s['host'] = $host;
            $s['db']   = $db;
            $port = (int)($p['port'] ?? $s['port']);
            $s['port'] = ($port >= 1 && $port <= 65535) ? $port : 3306; // empty/invalid => default
            $s['user'] = trim((string)($p['user'] ?? $s['user']));
            if (($p['pass'] ?? '') !== '') {
                $s['pass'] = (string)$p['pass'];
            }
            if ($k === 'remote') {
                $s['ssl']        = empty($p['ssl']) ? 0 : 1;
                $s['ssl_verify'] = empty($p['ssl_verify']) ? 0 : 1;
                $s['ca']         = trim((string)($p['ca'] ?? $s['ca']));
            }
            unset($s);
        }
        return $stored;
    }
}

/* ------------------------------------------------------------------ */
/* Web access control: localhost only, password login, CSRF           */
/* ------------------------------------------------------------------ */
final class Auth
{
    public static function boot(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!in_array($ip, ALLOWED_IPS, true)) {
            http_response_code(403);
            exit('Access restricted. Add your IP to ALLOWED_IPS in config.local.php only if you understand the risk.');
        }
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS'])]);
        session_name('dbmig');
        session_start();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
        }
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('Cache-Control: no-store');
    }

    private static function file(): string { return DATA_DIR . '/auth.json'; }
    public static function hasPassword(): bool { return is_file(self::file()); }

    public static function setPassword(string $p): void
    {
        file_put_contents(self::file(), json_encode(['hash' => password_hash($p, PASSWORD_DEFAULT)]), LOCK_EX);
        @chmod(self::file(), 0600);
    }

    public static function login(string $p): bool
    {
        $a = json_decode((string)@file_get_contents(self::file()), true);
        if (is_array($a) && password_verify($p, $a['hash'] ?? '')) {
            session_regenerate_id(true);
            $_SESSION['auth'] = 1;
            return true;
        }
        sleep(1); // slow down guessing
        return false;
    }

    public static function ok(): bool { return !empty($_SESSION['auth']); }
    public static function csrf(): string { return $_SESSION['csrf'] ?? ''; }
    public static function csrfOk(string $t): bool { return $t !== '' && hash_equals(self::csrf(), $t); }
}

/* ------------------------------------------------------------------ */
/* Job state file (locked read-modify-write)                           */
/* ------------------------------------------------------------------ */
final class Store
{
    private static function path(): string { return DATA_DIR . '/job.json'; }

    public static function read(): array
    {
        $h = fopen(self::path(), 'c+');
        flock($h, LOCK_SH);
        $raw = stream_get_contents($h);
        flock($h, LOCK_UN);
        fclose($h);
        $j = $raw ? json_decode($raw, true) : [];
        return is_array($j) ? $j : [];
    }

    public static function update(callable $fn): array
    {
        $h = fopen(self::path(), 'c+');
        flock($h, LOCK_EX);
        $raw = stream_get_contents($h);
        $j = $raw ? json_decode($raw, true) : [];
        if (!is_array($j)) { $j = []; }
        $fn($j);
        rewind($h);
        ftruncate($h, 0);
        fwrite($h, json_encode($j, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        fflush($h);
        flock($h, LOCK_UN);
        fclose($h);
        return $j;
    }

    public static function log(array &$j, string $level, string $msg): void
    {
        $j['log'][] = ['t' => time(), 'l' => $level, 'm' => $msg];
        if (count($j['log']) > 300) {
            $j['log'] = array_slice($j['log'], -200);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Job control used by both api.php and cli.php                        */
/* ------------------------------------------------------------------ */
final class Jobs
{
    public static function payload(array $j): array
    {
        if (!$j || empty($j['plan'])) {
            return ['status' => 'idle'];
        }
        $st = $j['status'];
        return [
            'status'      => $st,
            'interrupted' => $st === 'running' && (time() - ($j['heartbeat'] ?? 0)) > 30,
            'error'       => $j['error'] ?? null,
            'stats'       => $j['stats'] ?? new stdClass(),
            'log'         => array_slice($j['log'] ?? [], -80),
        ];
    }

    public static function start(array $opt, ?array $only): array
    {
        $lock = fopen(DATA_DIR . '/run.lock', 'c');
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('A transfer step is currently running. Pause it first.');
        }
        try {
            $cur = Store::read();
            if (($cur['status'] ?? '') === 'running' && (time() - ($cur['heartbeat'] ?? 0)) < 30) {
                throw new RuntimeException('A transfer is already running.');
            }
            $e    = new Engine(Config::load());
            $plan = $e->buildPlan($only);
            if (!$plan) {
                throw new RuntimeException('No tables selected / found in the local database.');
            }
            $opt = [
                'fresh' => !empty($opt['fresh']),
                'drop'  => !empty($opt['drop']),
                'views' => !isset($opt['views']) || !empty($opt['views']),
            ];
            if (!$opt['views']) {
                $plan = array_values(array_filter($plan, fn($p) => $p['type'] === 'table'));
            }
            $e->prepare($plan, $opt);
            $prog = $e->loadProgress();
            $now  = microtime(true);
            return Store::update(function (array &$j) use ($plan, $opt, $prog, $now) {
                $j = [
                    'id' => bin2hex(random_bytes(4)), 'status' => 'running', 'options' => $opt, 'plan' => $plan,
                    'started' => time(), 'heartbeat' => time(), 'tick' => $now, 'active' => 0, 'samples' => [],
                    'error' => null, 'log' => [], 'stats' => Engine::stats($plan, $prog, [], 0, null),
                ];
                Store::log($j, 'info', 'Started: ' . count($plan) . ' objects' . ($opt['fresh'] ? ' (fresh start)' : ''));
            });
        } finally {
            flock($lock, LOCK_UN);
        }
    }

    public static function setStatus(string $to): array
    {
        return Store::update(function (array &$j) use ($to) {
            if (empty($j['plan'])) { return; }
            $from = $j['status'];
            $ok = match ($to) {
                'paused'    => $from === 'running',
                'cancelled' => in_array($from, ['running', 'paused', 'failed'], true),
                'running'   => in_array($from, ['paused', 'failed', 'cancelled', 'running'], true),
                default     => false,
            };
            if (!$ok) { return; }
            $j['status'] = $to;
            if ($to === 'running') {
                $j['samples'] = [];
                $j['tick'] = microtime(true);
                $j['heartbeat'] = time();
                $j['error'] = null;
            }
            Store::log($j, 'info', ['paused' => 'Paused', 'cancelled' => 'Cancelled (progress kept; Resume or Start to continue)', 'running' => 'Resumed'][$to]);
        });
    }
}

/* ------------------------------------------------------------------ */
/* Schema / object comparison between the local and remote databases   */
/* ------------------------------------------------------------------ */
final class Differ
{
    private static function rows(PDO $p, string $sql): array
    {
        try { return $p->query($sql)->fetchAll(PDO::FETCH_ASSOC); } catch (Throwable) { return []; }
    }

    private static function norm(string $s, string $db): string
    {
        $s = str_replace('`', '', $s);
        $s = preg_replace('/\b' . preg_quote($db, '/') . '\./i', '', $s);
        return strtolower(trim(preg_replace('/\s+/', ' ', $s)));
    }

    private static function colSig(array $r): string
    {
        $t = strtolower($r['COLUMN_TYPE']);
        $t = preg_replace('/\b(smallint|mediumint|int|bigint)\(\d+\)/', '$1', $t);
        $t = preg_replace('/\btinyint\((?!1\))\d+\)/', 'tinyint', $t);
        $d = $r['COLUMN_DEFAULT'];
        $d = ($d === null || strtoupper((string)$d) === 'NULL') ? 'NULL' : strtolower(trim((string)$d, "'"));
        $d = str_replace('current_timestamp()', 'current_timestamp', $d);
        $e = trim(str_ireplace('DEFAULT_GENERATED', '', strtolower((string)$r['EXTRA'])));
        return trim("$t " . ($r['IS_NULLABLE'] === 'YES' ? 'NULL' : 'NOT NULL') . " default $d $e");
    }

    /** Compare two key=>string maps and append findings. */
    private static function cmp(array &$f, string $type, array $l, array $r, string $ctx = '', ?callable $explain = null): void
    {
        foreach ($l as $k => $v) {
            if (!array_key_exists($k, $r)) {
                $f[] = ['type' => $type, 'status' => 'only_local', 'name' => $ctx . $k, 'detail' => ''];
            } elseif ($r[$k] !== $v) {
                $f[] = ['type' => $type, 'status' => 'different', 'name' => $ctx . $k,
                        'detail' => $explain ? $explain($v, $r[$k]) : "local: $v  |  remote: {$r[$k]}"];
            }
        }
        foreach ($r as $k => $v) {
            if (!array_key_exists($k, $l)) {
                $f[] = ['type' => $type, 'status' => 'only_remote', 'name' => $ctx . $k, 'detail' => ''];
            }
        }
    }

    /** Load every compared object class of one database. */
    private static function load(PDO $p, bool $counts): array
    {
        $db = (string)$p->query("SELECT DATABASE()")->fetchColumn();
        $o = ['db' => $db, 'tables' => [], 'views' => [], 'cols' => [], 'idx' => [], 'fk' => [],
              'trg' => [], 'rtn' => [], 'evt' => [], 'viewdef' => [], 'count' => []];
        foreach (self::rows($p, "SELECT TABLE_NAME n, TABLE_TYPE t FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE IN ('BASE TABLE','VIEW')") as $r) {
            $o[$r['t'] === 'VIEW' ? 'views' : 'tables'][strtolower($r['n'])] = $r['n'];
        }
        foreach (self::rows($p, "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, ORDINAL_POSITION") as $r) {
            $o['cols'][strtolower($r['TABLE_NAME'])][$r['COLUMN_NAME']] = self::colSig($r);
        }
        $tmp = [];
        foreach (self::rows($p, "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, COLUMN_NAME, SUB_PART, INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX") as $r) {
            $k = strtolower($r['TABLE_NAME']);
            $tmp[$k][$r['INDEX_NAME']]['c'][] = $r['COLUMN_NAME'] . ($r['SUB_PART'] ? "({$r['SUB_PART']})" : '');
            $tmp[$k][$r['INDEX_NAME']]['m'] = ($r['NON_UNIQUE'] ? '' : 'UNIQUE ') . (in_array($r['INDEX_TYPE'], ['FULLTEXT', 'SPATIAL'], true) ? $r['INDEX_TYPE'] . ' ' : '');
        }
        foreach ($tmp as $t => $ix) { foreach ($ix as $n => $d) { $o['idx'][$t][$n] = $d['m'] . '(' . implode(',', $d['c']) . ')'; } }
        $tmp = [];
        foreach (self::rows($p, "SELECT k.TABLE_NAME, k.CONSTRAINT_NAME, k.COLUMN_NAME, k.REFERENCED_TABLE_NAME rt, k.REFERENCED_COLUMN_NAME rc, r.UPDATE_RULE ur, r.DELETE_RULE dr
            FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r
              ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME AND r.TABLE_NAME = k.TABLE_NAME
            WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY k.TABLE_NAME, k.CONSTRAINT_NAME, k.ORDINAL_POSITION") as $r) {
            $x = &$tmp[strtolower($r['TABLE_NAME'])][$r['CONSTRAINT_NAME']];
            $x['c'][] = $r['COLUMN_NAME']; $x['rc'][] = $r['rc']; $x['rt'] = strtolower($r['rt']);
            $x['rule'] = 'ON UPDATE ' . str_replace('RESTRICT', 'NO ACTION', $r['ur']) . ' ON DELETE ' . str_replace('RESTRICT', 'NO ACTION', $r['dr']);
            unset($x);
        }
        foreach ($tmp as $t => $fk) { foreach ($fk as $n => $d) { $o['fk'][$t][$n] = '(' . implode(',', $d['c']) . ") -> {$d['rt']}(" . implode(',', $d['rc']) . ") {$d['rule']}"; } }
        foreach (self::rows($p, "SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()") as $r) {
            $o['trg'][$r['TRIGGER_NAME']] = strtolower("{$r['ACTION_TIMING']} {$r['EVENT_MANIPULATION']} ON {$r['EVENT_OBJECT_TABLE']}") . "\x1f" . self::norm((string)$r['ACTION_STATEMENT'], $db);
        }
        foreach (self::rows($p, "SELECT ROUTINE_TYPE, ROUTINE_NAME, ROUTINE_DEFINITION, DTD_IDENTIFIER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE()") as $r) {
            $o['rtn'][$r['ROUTINE_TYPE'] . ' ' . $r['ROUTINE_NAME']] = strtolower((string)$r['DTD_IDENTIFIER']) . "\x1f" . self::norm((string)$r['ROUTINE_DEFINITION'], $db);
        }
        foreach (self::rows($p, "SELECT EVENT_NAME, EVENT_DEFINITION, INTERVAL_VALUE, INTERVAL_FIELD, STATUS FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE()") as $r) {
            $o['evt'][$r['EVENT_NAME']] = strtolower("every {$r['INTERVAL_VALUE']} {$r['INTERVAL_FIELD']} {$r['STATUS']}") . "\x1f" . self::norm((string)$r['EVENT_DEFINITION'], $db);
        }
        foreach (self::rows($p, "SELECT TABLE_NAME, VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE()") as $r) {
            $o['viewdef'][strtolower($r['TABLE_NAME'])] = self::norm((string)$r['VIEW_DEFINITION'], $db);
        }
        if ($counts) {
            foreach ($o['tables'] as $k => $name) {
                try { $o['count'][$k] = (int)$p->query("SELECT COUNT(*) FROM `$name`")->fetchColumn(); } catch (Throwable) {}
            }
        }
        return $o;
    }

    public static function run(array $cfg, bool $counts): array
    {
        $L = self::load(Engine::pdo($cfg['local'], false), $counts);
        $R = self::load(Engine::pdo($cfg['remote'], true), $counts);
        $f = [];

        // tables / views on one side only (case-insensitive match; case-only differences are reported)
        foreach (['tables' => 'table', 'views' => 'view'] as $key => $type) {
            $other = $key === 'tables' ? 'views' : 'tables';
            foreach ($L[$key] as $k => $n) {
                if (!isset($R[$key][$k])) {
                    $f[] = ['type' => $type, 'status' => 'only_local', 'name' => $n, 'detail' => isset($R[$other][$k]) ? 'exists on remote as a ' . ($key === 'tables' ? 'view' : 'table') : ''];
                } elseif ($R[$key][$k] !== $n) {
                    $f[] = ['type' => $type, 'status' => 'different', 'name' => $n, 'detail' => "name case differs (remote: {$R[$key][$k]})"];
                }
            }
            foreach ($R[$key] as $k => $n) {
                if (!isset($L[$key][$k])) {
                    $f[] = ['type' => $type, 'status' => 'only_remote', 'name' => $n, 'detail' => isset($L[$other][$k]) ? 'exists on local as a ' . ($key === 'tables' ? 'view' : 'table') : ''];
                }
            }
        }

        // per-table structure for tables that exist on both sides
        foreach (array_keys(array_intersect_key($L['tables'], $R['tables'])) as $k) {
            $name = $L['tables'][$k];
            self::cmp($f, 'column', $L['cols'][$k] ?? [], $R['cols'][$k] ?? [], "$name.");
            self::cmp($f, 'index', $L['idx'][$k] ?? [], $R['idx'][$k] ?? [], "$name.");
            self::cmp($f, 'foreign key', $L['fk'][$k] ?? [], $R['fk'][$k] ?? [], "$name.");
            if (isset($L['count'][$k], $R['count'][$k]) && $L['count'][$k] !== $R['count'][$k]) {
                $f[] = ['type' => 'row count', 'status' => 'different', 'name' => $name,
                        'detail' => 'local ' . number_format($L['count'][$k]) . '  |  remote ' . number_format($R['count'][$k])];
            }
        }
        foreach (array_intersect_key($L['viewdef'], $R['viewdef']) as $k => $def) {
            if ($def !== $R['viewdef'][$k]) {
                $f[] = ['type' => 'view', 'status' => 'different', 'name' => $L['views'][$k] ?? $k, 'detail' => 'definition differs'];
            }
        }

        $explain = function (string $l, string $r): string {
            [$lh] = explode("\x1f", $l, 2);
            [$rh] = explode("\x1f", $r, 2);
            return $lh !== $rh ? "header differs - local: $lh  |  remote: $rh" : 'body/definition differs';
        };
        self::cmp($f, 'trigger', $L['trg'], $R['trg'], '', $explain);
        self::cmp($f, 'routine', $L['rtn'], $R['rtn'], '', $explain);
        self::cmp($f, 'event', $L['evt'], $R['evt'], '', $explain);

        return [
            'findings' => $f,
            'info' => [
                'local' => $L['db'], 'remote' => $R['db'],
                'tables_local' => count($L['tables']), 'tables_remote' => count($R['tables']),
                'views_local' => count($L['views']), 'views_remote' => count($R['views']),
                'triggers_local' => count($L['trg']), 'triggers_remote' => count($R['trg']),
                'routines_local' => count($L['rtn']), 'routines_remote' => count($R['rtn']),
                'events_local' => count($L['evt']), 'events_remote' => count($R['evt']),
                'row_counts' => $counts,
            ],
        ];
    }
}

/* ------------------------------------------------------------------ */
/* Transfer engine                                                     */
/* ------------------------------------------------------------------ */
final class Engine
{
    private const PROG = '__migrator_progress';
    private PDO $src;
    private PDO $dst;
    private int $packet = 4194304;
    private array $meta = [];
    private array $rowsPer = [];

    public function __construct(private array $cfg)
    {
        $this->connect();
    }

    public static function pdo(array $c, bool $remote): PDO
    {
        if ($c['host'] === '' || $c['db'] === '' || $c['user'] === '') {
            throw new RuntimeException(($remote ? 'Remote' : 'Local') . ' host, database and user are required.');
        }
        $opt = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => true,
            PDO::ATTR_STRINGIFY_FETCHES => true,
            PDO::ATTR_TIMEOUT => 15,
            PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
        ];
        if ($remote && !empty($c['ssl'])) {
            $opt[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = !empty($c['ssl_verify']);
            if ($c['ca'] !== '') { $opt[PDO::MYSQL_ATTR_SSL_CA] = $c['ca']; }
            else { $opt[PDO::MYSQL_ATTR_SSL_CIPHER] = 'DEFAULT'; } // forces TLS without a CA file
        }
        $pdo = new PDO("mysql:host={$c['host']};port={$c['port']};dbname={$c['db']};charset=utf8mb4", $c['user'], $c['pass'], $opt);
        $pdo->exec("SET NAMES utf8mb4");
        $pdo->exec("SET time_zone = '+00:00'");
        if ($remote) {
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
            $pdo->exec("SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'");
            try { $pdo->exec("SET SESSION wait_timeout = 900"); } catch (Throwable) {}
        }
        return $pdo;
    }

    public static function test(array $c, bool $remote): array
    {
        $pdo = self::pdo($c, $remote);
        $n = (int)$pdo->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()")->fetchColumn();
        return ['version' => $pdo->query("SELECT VERSION()")->fetchColumn(), 'tables' => $n];
    }

    private function connect(): void
    {
        $this->src = self::pdo($this->cfg['local'], false);
        $this->dst = self::pdo($this->cfg['remote'], true);
        $this->packet = max(65536, (int)$this->dst->query("SELECT @@max_allowed_packet")->fetchColumn());
    }

    /* ---------- planning ---------- */

    public function listObjects(): array
    {
        $rows = $this->src->query(
            "SELECT TABLE_NAME n, TABLE_TYPE t, COALESCE(TABLE_ROWS,0) r, COALESCE(DATA_LENGTH,0) d, COALESCE(AVG_ROW_LENGTH,0) a
             FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE IN ('BASE TABLE','VIEW')
             ORDER BY (TABLE_TYPE = 'VIEW'), TABLE_NAME"
        )->fetchAll(PDO::FETCH_ASSOC);
        $out = [];
        foreach ($rows as $r) {
            $out[] = [
                'name' => $r['n'], 'type' => $r['t'] === 'VIEW' ? 'view' : 'table',
                'rows' => (int)$r['r'], 'bytes' => max(1, (int)$r['d']), 'avg' => max(1, (int)$r['a']),
            ];
        }
        return $out;
    }

    public function buildPlan(?array $only): array
    {
        $all = $this->listObjects();
        return array_values(array_filter($all, fn($o) => $only === null || in_array($o['name'], $only, true)));
    }

    /** Create remote schema + progress rows for tables not yet prepared. */
    public function prepare(array $plan, array $opt): void
    {
        $this->dst->exec("CREATE TABLE IF NOT EXISTS `" . self::PROG . "` (
            tbl VARCHAR(191) NOT NULL PRIMARY KEY, last_key MEDIUMTEXT NULL,
            rows_done BIGINT NOT NULL DEFAULT 0, done TINYINT NOT NULL DEFAULT 0, updated_at DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        if ($opt['fresh']) {
            $this->dst->exec("DELETE FROM `" . self::PROG . "`");
        }
        $existing = $this->loadProgress();
        foreach ($plan as $it) {
            $t = $it['name'];
            if ($it['type'] === 'view' || isset($existing[$t])) {
                continue;
            }
            if ($opt['drop']) {
                $this->dst->exec("DROP TABLE IF EXISTS `$t`");
            }
            $ddl = $this->src->query("SHOW CREATE TABLE `$t`")->fetch(PDO::FETCH_NUM)[1];
            $this->dst->exec(preg_replace('/^CREATE TABLE/', 'CREATE TABLE IF NOT EXISTS', $ddl, 1));
            if (!$this->meta($t)['pk']) {
                $this->dst->exec("TRUNCATE TABLE `$t`"); // no key => cannot dedupe, so start the table empty
            }
            $this->saveProgress($t, null, 0, false);
        }
        foreach ($plan as $it) {
            if ($it['type'] === 'view' && !isset($existing[$it['name']])) {
                $this->saveProgress($it['name'], null, 0, false);
            }
        }
    }

    public function loadProgress(): array
    {
        $out = [];
        foreach ($this->dst->query("SELECT tbl, last_key, rows_done, done FROM `" . self::PROG . "`") as $r) {
            $out[$r['tbl']] = ['key' => $r['last_key'], 'rows' => (int)$r['rows_done'], 'done' => (bool)(int)$r['done']];
        }
        return $out;
    }

    private function saveProgress(string $t, ?string $key, int $rows, bool $done): void
    {
        $this->dst->exec(sprintf(
            "INSERT INTO `%s` (tbl,last_key,rows_done,done,updated_at) VALUES (%s,%s,%d,%d,NOW())
             ON DUPLICATE KEY UPDATE last_key=VALUES(last_key), rows_done=VALUES(rows_done), done=VALUES(done), updated_at=NOW()",
            self::PROG, $this->dst->quote($t), $key === null ? 'NULL' : $this->dst->quote($key), $rows, $done ? 1 : 0
        ));
    }

    /* ---------- table metadata & SQL literals ---------- */

    private function meta(string $t): array
    {
        if (isset($this->meta[$t])) {
            return $this->meta[$t];
        }
        $st = $this->src->prepare("SELECT COLUMN_NAME, DATA_TYPE, EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION");
        $st->execute([$t]);
        $cols = [];
        foreach ($st->fetchAll(PDO::FETCH_NUM) as [$name, $type, $extra]) {
            if (preg_match('/(VIRTUAL|STORED) GENERATED|PERSISTENT/i', (string)$extra)) {
                continue; // generated columns are computed by the server
            }
            $cols[$name] = strtolower($type);
        }
        $st = $this->src->prepare("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX");
        $st->execute([$t]);
        $pk = array_values(array_filter($st->fetchAll(PDO::FETCH_COLUMN), fn($c) => isset($cols[$c])));
        $names = array_keys($cols);
        $sel = array_map(fn($c) => in_array($cols[$c], ['geometry', 'point', 'linestring', 'polygon', 'multipoint', 'multilinestring', 'multipolygon', 'geometrycollection'], true)
            ? "ST_AsText(`$c`) AS `$c`" : "`$c`", $names);
        return $this->meta[$t] = [
            'cols' => $cols, 'names' => $names, 'sel' => $sel, 'pk' => $pk,
            'pkIdx' => array_map(fn($c) => array_search($c, $names, true), $pk),
        ];
    }

    private function lit(PDO $c, ?string $v, string $type): string
    {
        if ($v === null) { return 'NULL'; }
        switch ($type) {
            case 'binary': case 'varbinary': case 'tinyblob': case 'blob': case 'mediumblob': case 'longblob': case 'bit':
                return $v === '' ? "''" : '0x' . bin2hex($v);
            case 'geometry': case 'point': case 'linestring': case 'polygon': case 'multipoint':
            case 'multilinestring': case 'multipolygon': case 'geometrycollection':
                return 'ST_GeomFromText(' . $c->quote($v) . ')';
        }
        if (preg_match('/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/', $v) && preg_match('/int|decimal|numeric|float|double|real|year/', $type)) {
            return $v;
        }
        return $c->quote($v);
    }

    private function keyCond(array $m, array $vals): string
    {
        $or = [];
        for ($i = 0, $n = count($m['pk']); $i < $n; $i++) {
            $and = [];
            for ($j = 0; $j < $i; $j++) {
                $and[] = "`{$m['pk'][$j]}` = " . $this->lit($this->src, $vals[$j], $m['cols'][$m['pk'][$j]]);
            }
            $and[] = "`{$m['pk'][$i]}` > " . $this->lit($this->src, $vals[$i], $m['cols'][$m['pk'][$i]]);
            $or[] = '(' . implode(' AND ', $and) . ')';
        }
        return implode(' OR ', $or);
    }

    /* ---------- one batch = one remote transaction (data + progress) ---------- */

    private function batch(string $t, array $p, int $n): array
    {
        $m = $this->meta($t);
        $sql = "SELECT " . implode(',', $m['sel']) . " FROM `$t`";
        if ($m['pk']) {
            if ($p['key'] !== null) {
                $vals = array_map('base64_decode', json_decode($p['key'], true));
                $sql .= " WHERE " . $this->keyCond($m, $vals);
            }
            $sql .= " ORDER BY `" . implode('`,`', $m['pk']) . "`";
            $sql .= " LIMIT $n";
        } else {
            $sql .= " LIMIT $n OFFSET {$p['rows']}";
        }
        $rows = $this->src->query($sql)->fetchAll(PDO::FETCH_NUM);
        $cnt  = count($rows);
        $sent = 0;
        $cols = $m['names'];
        $types = array_values($m['cols']);

        $this->dst->beginTransaction();
        if ($cnt) {
            $nonKey = array_diff($cols, $m['pk']);
            $verb   = ($m['pk'] && !$nonKey) ? 'INSERT IGNORE' : 'INSERT';
            $head   = "$verb INTO `$t` (`" . implode('`,`', $cols) . "`) VALUES ";
            $tail   = ($m['pk'] && $nonKey)
                ? ' ON DUPLICATE KEY UPDATE ' . implode(',', array_map(fn($c) => "`$c`=VALUES(`$c`)", $nonKey)) : '';
            $limit  = (int)min($this->packet * 0.9, 4 * 1024 * 1024) - strlen($head) - strlen($tail);
            $buf = []; $len = 0;
            $flush = function () use (&$buf, &$len, &$sent, $head, $tail) {
                if ($buf) {
                    $this->dst->exec($head . implode(',', $buf) . $tail);
                    $sent += $len;
                    $buf = []; $len = 0;
                }
            };
            foreach ($rows as $r) {
                $lits = [];
                foreach ($r as $i => $v) { $lits[] = $this->lit($this->dst, $v, $types[$i]); }
                $tuple = '(' . implode(',', $lits) . ')';
                if ($buf && $len + strlen($tuple) + 1 > $limit) { $flush(); }
                $buf[] = $tuple;
                $len += strlen($tuple) + 1;
            }
            $flush();
        }
        $done = $cnt < $n;
        $key  = $p['key'];
        if ($cnt && $m['pk']) {
            $last = $rows[$cnt - 1];
            $key  = json_encode(array_map(fn($i) => base64_encode((string)$last[$i]), $m['pkIdx']));
        }
        $total = $p['rows'] + $cnt;
        $this->saveProgress($t, $key, $total, $done);
        $this->dst->commit();
        return ['key' => $key, 'rows' => $total, 'done' => $done, 'cnt' => $cnt, 'sent' => $sent];
    }

    private static function transient(PDOException $x): bool
    {
        $code = (int)($x->errorInfo[1] ?? 0);
        return in_array($code, [2002, 2003, 2006, 2013, 1205, 1213, 1053, 1317], true)
            || (bool)preg_match('/gone away|lost connection|timed out|broken pipe/i', $x->getMessage());
    }

    /* ---------- progress statistics ---------- */

    public static function stats(array $plan, array $prog, array $samples, float $active, ?string $current): array
    {
        $total = $done = 0; $rows = 0; $tdone = 0; $list = [];
        foreach ($plan as $it) {
            $p = $prog[$it['name']] ?? ['rows' => 0, 'done' => false];
            $frac = $p['done'] ? 1.0 : min(0.99, $p['rows'] / max(1, $it['rows']));
            $total += $it['bytes'];
            $done  += (int)round($it['bytes'] * $frac);
            $rows  += $p['rows'];
            $tdone += $p['done'] ? 1 : 0;
            $list[] = [$it['name'], $p['done'] ? 'done' : ($it['name'] === $current ? 'active' : 'wait'), (int)round($frac * 100)];
        }
        $speed = 0.0;
        if (count($samples) >= 2) {
            $a = $samples[0]; $b = end($samples);
            if ($b[0] - $a[0] > 0.5) { $speed = max(0, ($b[1] - $a[1]) / ($b[0] - $a[0])); }
        }
        $remain = max(0, $total - $done);
        return [
            'bytes_total' => $total, 'bytes_done' => $done, 'bytes_left' => $remain,
            'percent' => $total ? round($done / $total * 100, 2) : 100,
            'speed' => (int)$speed, 'eta' => $speed > 0 ? (int)($remain / $speed) : null,
            'elapsed' => (int)$active, 'rows_done' => $rows, 'tables_done' => $tdone, 'tables_total' => count($plan),
            'current' => $current, 'tables' => $list,
        ];
    }

    /* ---------- one time-boxed step (called repeatedly by the browser or the CLI) ---------- */

    public static function step(): array
    {
        $lock = fopen(DATA_DIR . '/run.lock', 'c');
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            return Jobs::payload(Store::read()) + ['busy' => true];
        }
        ignore_user_abort(true);
        try {
            return self::runStep();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function fail(string $msg): array
    {
        return Jobs::payload(Store::update(function (array &$j) use ($msg) {
            $j['status'] = 'failed';
            $j['error']  = $msg;
            Store::log($j, 'error', $msg);
        }));
    }

    private static function runStep(): array
    {
        $job = Store::read();
        if (($job['status'] ?? '') !== 'running') {
            return Jobs::payload($job);
        }
        $maxExec = (int)ini_get('max_execution_time');
        $budget  = $maxExec > 0 ? max(3, min(STEP_SECONDS, $maxExec - 8)) : STEP_SECONDS;
        @set_time_limit($budget + 60);
        $deadline = microtime(true) + $budget;
        $plan = $job['plan'];
        $current = null;
        $prog = [];

        try {
            $e = new self(Config::load());
            $prog = $e->loadProgress();
        } catch (Throwable $t) {
            return self::fail('Connection failed: ' . $t->getMessage());
        }

        // Persist stats + heartbeat; returns false when the user paused/cancelled.
        $persist = function (int $sent = 0) use (&$prog, $plan, &$current): bool {
            $keep = true;
            Store::update(function (array &$j) use (&$prog, $plan, &$current, &$keep) {
                if ($j['status'] !== 'running') { $keep = false; }
                $now = microtime(true);
                if ($j['status'] === 'running') {
                    $dt = $now - ($j['tick'] ?? $now);
                    $j['active'] = ($j['active'] ?? 0) + (($dt > 0 && $dt < 30) ? $dt : 0);
                    $j['tick'] = $now;
                    $j['heartbeat'] = time();
                }
                $s = Engine::stats($plan, $prog, [], $j['active'] ?? 0, $current);
                $sam = $j['samples'] ?? [];
                $sam[] = [$now, $s['bytes_done']];
                while (count($sam) > 2 && $now - $sam[0][0] > 20) { array_shift($sam); }
                $j['samples'] = $sam;
                $j['stats'] = Engine::stats($plan, $prog, $sam, $j['active'] ?? 0, $current);
            });
            return $keep;
        };

        try {
            foreach ($plan as $it) {
                $t = $it['name'];
                $p = $prog[$t] ?? ['key' => null, 'rows' => 0, 'done' => false];
                if ($p['done']) { continue; }
                $current = $t;

                if ($it['type'] === 'view') {
                    $ddl = $e->src->query("SHOW CREATE VIEW `$t`")->fetch(PDO::FETCH_NUM)[1];
                    $ddl = preg_replace('/^CREATE\s.*?\sVIEW/is', 'CREATE OR REPLACE VIEW', $ddl, 1);
                    $e->dst->exec($ddl);
                    $e->saveProgress($t, null, 0, true);
                    $prog[$t] = ['key' => null, 'rows' => 0, 'done' => true];
                    Store::update(fn(array &$j) => Store::log($j, 'info', "View $t created"));
                    continue;
                }

                $n = $e->rowsPer[$t] ?? max(1, min(MAX_BATCH_ROWS, intdiv(BATCH_BYTES, $it['avg'])));
                while (!$p['done']) {
                    if (microtime(true) >= $deadline) { break 2; }
                    $attempt = 0;
                    while (true) {
                        try {
                            $r = $e->batch($t, $p, $n);
                            break;
                        } catch (PDOException $x) {
                            if ($e->dst->inTransaction()) { try { $e->dst->rollBack(); } catch (Throwable) {} }
                            if (!self::transient($x) || ++$attempt > 3) {
                                throw new RuntimeException("Table `$t` after {$p['rows']} rows: " . $x->getMessage(), 0, $x);
                            }
                            Store::update(fn(array &$j) => Store::log($j, 'warn', "Retrying `$t` (attempt $attempt): " . $x->getMessage()));
                            sleep(min(8, 2 ** $attempt));
                            $e->connect();
                        }
                    }
                    $p = ['key' => $r['key'], 'rows' => $r['rows'], 'done' => $r['done']];
                    $prog[$t] = $p;
                    if ($r['sent'] > 0) {
                        $n = max(1, min(MAX_BATCH_ROWS, (int)round(($n + $n * BATCH_BYTES / $r['sent']) / 2)));
                        $e->rowsPer[$t] = $n;
                    }
                    if ($p['done']) {
                        $rc = (int)$e->dst->query("SELECT COUNT(*) FROM `$t`")->fetchColumn();
                        $msg = "Table $t done ({$p['rows']} rows)" . ($rc !== $p['rows'] ? " – WARNING remote has $rc rows" : '');
                        $lvl = $rc !== $p['rows'] ? 'warn' : 'ok';
                        Store::update(fn(array &$j) => Store::log($j, $lvl, $msg));
                    }
                    if (!$persist($r['sent'])) {
                        return Jobs::payload(Store::read()); // paused / cancelled by the user
                    }
                }
            }
        } catch (Throwable $t) {
            $persist();
            return self::fail($t->getMessage());
        }

        $persist();
        $allDone = true;
        foreach ($plan as $it) { $allDone = $allDone && !empty($prog[$it['name']]['done']); }
        if ($allDone) {
            try { $e->dst->exec("DROP TABLE IF EXISTS `" . self::PROG . "`"); } catch (Throwable) {}
            return Jobs::payload(Store::update(function (array &$j) {
                if ($j['status'] === 'running') {
                    $j['status'] = 'completed';
                    $j['stats']['percent'] = 100;
                    $j['stats']['eta'] = 0;
                    Store::log($j, 'ok', 'Migration completed successfully');
                }
            }));
        }
        return Jobs::payload(Store::read());
    }
}
