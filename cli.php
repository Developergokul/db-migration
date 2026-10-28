<?php
declare(strict_types=1);
/**
 * Command-line runner (no browser, no web timeouts).
 *   php cli.php start [--fresh] [--drop] [--no-views] [--tables=a,b,c]
 *   php cli.php resume
 *   php cli.php status
 * Uses the credentials saved from the web UI.
 */
if (PHP_SAPI !== 'cli') { exit('CLI only'); }
require __DIR__ . '/lib.php';

$cmd  = $argv[1] ?? 'status';
$args = array_slice($argv, 2);
$fmt  = function (int $b): string {
    foreach (['B', 'KB', 'MB', 'GB'] as $i => $u) { if ($b < 1024 ** ($i + 1) || $u === 'GB') { return round($b / 1024 ** $i, 2) . " $u"; } }
};
$line = function (array $p) use ($fmt): string {
    $s = (array)($p['stats'] ?? []);
    if (!$s) { return $p['status']; }
    return sprintf("[%s] %5.1f%%  %s / %s  %s/s  ETA %s  %s", $p['status'], $s['percent'], $fmt($s['bytes_done']), $fmt($s['bytes_total']),
        $fmt($s['speed']), $s['eta'] === null ? '--' : gmdate('H:i:s', $s['eta']), $s['current'] ?? '');
};

try {
    if ($cmd === 'start') {
        $only = null;
        foreach ($args as $a) { if (str_starts_with($a, '--tables=')) { $only = explode(',', substr($a, 9)); } }
        Jobs::start(['fresh' => in_array('--fresh', $args), 'drop' => in_array('--drop', $args), 'views' => !in_array('--no-views', $args)], $only);
    } elseif ($cmd === 'resume') {
        Jobs::setStatus('running');
    } else {
        echo $line(Jobs::payload(Store::read())), PHP_EOL;
        exit(0);
    }
    do {
        $p = Engine::step();
        echo "\r", str_pad($line($p), 110);
        if (!empty($p['busy'])) { sleep(1); }
    } while ($p['status'] === 'running');
    echo PHP_EOL, $p['status'] === 'completed' ? 'Done.' : 'Stopped: ' . $p['status'] . ' ' . ($p['error'] ?? ''), PHP_EOL;
    exit($p['status'] === 'completed' ? 0 : 1);
} catch (Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
