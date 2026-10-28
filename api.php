<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';

Auth::boot();
header('Content-Type: application/json; charset=utf-8');

function out(array $d, int $code = 200)
{
    http_response_code($code);
    echo json_encode($d, JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !Auth::ok()) {
    out(['error' => 'Not authorised'], 401);
}
if (!Auth::csrfOk($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
    out(['error' => 'Bad CSRF token – reload the page'], 403);
}
session_write_close(); // do not hold the session lock during long steps (pause must get through)

$in     = json_decode((string)file_get_contents('php://input'), true) ?: [];
$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'config':
            out(['config' => Config::masked(Config::load())]);

        case 'save':
            Config::save(Config::merge(Config::load(), $in));
            out(['ok' => true, 'config' => Config::masked(Config::load())]);

        case 'test':
            $side = ($in['side'] ?? '') === 'remote' ? 'remote' : 'local';
            $cfg  = Config::merge(Config::load(), $in);
            out(['ok' => true] + Engine::test($cfg[$side], $side === 'remote'));

        case 'clear':
            $side = $in['side'] ?? '';
            if (!in_array($side, ['local', 'remote'], true)) { throw new InvalidArgumentException('Unknown side'); }
            $c = Config::load();
            $c[$side] = Config::defaults()[$side];
            Config::save($c);
            out(['ok' => true, 'config' => Config::masked($c)]);

        case 'clearjob':
            $j = Store::read();
            if (($j['status'] ?? '') === 'running' && (time() - ($j['heartbeat'] ?? 0)) < 30) {
                throw new RuntimeException('A transfer is running. Pause or cancel it first.');
            }
            Store::update(function (array &$j) { $j = []; });
            out(Jobs::payload([]));

        case 'diff':
            @set_time_limit(600);
            out(Differ::run(Config::load(), !empty($in['counts'])));

        case 'tables':
            out(['tables' => (new Engine(Config::load()))->listObjects()]);

        case 'start':
            $only = isset($in['tables']) && is_array($in['tables']) ? array_map('strval', $in['tables']) : null;
            out(Jobs::payload(Jobs::start($in['options'] ?? [], $only)));

        case 'step':
            out(Engine::step());

        case 'status':
            out(Jobs::payload(Store::read()));

        case 'pause':
            out(Jobs::payload(Jobs::setStatus('paused')));

        case 'resume':
            out(Jobs::payload(Jobs::setStatus('running')));

        case 'cancel':
            out(Jobs::payload(Jobs::setStatus('cancelled')));

        default:
            out(['error' => 'Unknown action'], 400);
    }
} catch (Throwable $e) {
    out(['error' => $e->getMessage()], 400);
}
