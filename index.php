<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
Auth::boot();

$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$err = '';

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: index.php');
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pw'])) {
    if (!Auth::csrfOk((string)($_POST['csrf'] ?? ''))) {
        $err = 'Session expired, try again.';
    } elseif (!Auth::hasPassword()) {
        if (strlen($_POST['pw']) < 8) { $err = 'Use at least 8 characters.'; }
        elseif ($_POST['pw'] !== ($_POST['pw2'] ?? '')) { $err = 'Passwords do not match.'; }
        else { Auth::setPassword($_POST['pw']); Auth::login($_POST['pw']); header('Location: index.php'); exit; }
    } elseif (Auth::login($_POST['pw'])) {
        header('Location: index.php');
        exit;
    } else {
        $err = 'Wrong password.';
    }
}
$authed = Auth::ok();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DB Migrator</title>
<link rel="stylesheet" href="assets/app.css">
</head>
<body>
<?php if (!$authed): ?>
<main class="narrow">
  <div class="card">
    <h1>DB Migrator</h1>
    <p class="muted"><?= Auth::hasPassword() ? 'Sign in to continue.' : 'First run: choose a password that protects this tool (min. 8 characters).' ?></p>
    <?php if ($err): ?><div class="alert bad"><?= $h($err) ?></div><?php endif; ?>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= $h(Auth::csrf()) ?>">
      <label>Password<input type="password" name="pw" required autofocus></label>
      <?php if (!Auth::hasPassword()): ?><label>Repeat password<input type="password" name="pw2" required></label><?php endif; ?>
      <button class="btn primary" type="submit"><?= Auth::hasPassword() ? 'Sign in' : 'Set password' ?></button>
    </form>
  </div>
</main>
<?php else: ?>
<main>
  <header>
    <div><h1>DB Migrator</h1><span class="muted">Local MySQL &rarr; remote MySQL, in resumable batches</span></div>
    <a class="link" href="?logout=1">Sign out</a>
  </header>

  <section class="grid2">
    <?php foreach (['local' => 'Local (source)', 'remote' => 'Remote (destination)'] as $k => $title): ?>
    <div class="card" data-side="<?= $k ?>">
      <h2><?= $title ?></h2>
      <div class="row"><label class="grow">Host<input name="host" autocomplete="off"></label><label class="port">Port<input name="port" type="number" autocomplete="off"></label></div>
      <label>Database<input name="db" autocomplete="off"></label>
      <label>User<input name="user" autocomplete="off"></label>
      <label>Password<input name="pass" type="password" autocomplete="new-password" placeholder=""></label>
      <?php if ($k === 'remote'): ?>
      <div class="row checks">
        <label class="inline"><input type="checkbox" name="ssl"> Use SSL/TLS</label>
        <label class="inline"><input type="checkbox" name="ssl_verify"> Verify certificate</label>
      </div>
      <label>CA file path <span class="muted">(optional)</span><input name="ca" autocomplete="off"></label>
      <?php endif; ?>
      <div class="row">
        <button class="btn" data-test="<?= $k ?>">Test connection</button>
        <button class="btn" data-clear="<?= $k ?>" title="Remove the saved details for this database">Clear</button>
        <span class="test-result muted"></span>
      </div>
    </div>
    <?php endforeach; ?>
  </section>
  <div class="row end"><span id="saveMsg" class="muted"></span><button class="btn" id="saveBtn">Save credentials</button></div>

  <section class="card">
    <h2>Options</h2>
    <div class="row checks">
      <label class="inline"><input type="checkbox" id="optFresh"> Start fresh (ignore saved progress)</label>
      <label class="inline"><input type="checkbox" id="optDrop"> Drop &amp; recreate remote tables</label>
      <label class="inline"><input type="checkbox" id="optViews" checked> Copy views</label>
    </div>
    <div class="row checks">
      <label class="inline"><input type="radio" name="scope" value="all" checked> All tables</label>
      <label class="inline"><input type="radio" name="scope" value="selected"> Selected tables only (one or more)</label>
    </div>
    <div id="tablePicker" hidden>
      <div class="row">
        <input id="tableFilter" placeholder="Filter tables…" style="max-width:240px;margin:0">
        <button class="btn small" id="loadTables">Reload list</button>
        <label class="inline"><input type="checkbox" id="allTables"> Select all</label>
        <span class="muted" id="tableCount"></span>
      </div>
      <div id="tableList" class="tablelist"></div>
    </div>
  </section>

  <section class="card" id="progressCard">
    <div class="row between">
      <h2>Transfer</h2><div class="row"><button class="btn small" id="btnClearJob" title="Forget the last transfer's progress/log">Clear</button><button class="btn small" id="btnRefresh" title="Reload status">&#8635; Refresh</button><span id="pill" class="pill">idle</span></div>
    </div>
    <div class="bar"><div id="barFill"></div><span id="barText">0%</span></div>
    <div class="stats">
      <div><small>Uploaded</small><b id="sDone">–</b></div>
      <div><small>Remaining</small><b id="sLeft">–</b></div>
      <div><small>Total</small><b id="sTotal">–</b></div>
      <div><small>Speed</small><b id="sSpeed">–</b></div>
      <div><small>Time left</small><b id="sEta">–</b></div>
      <div><small>Elapsed</small><b id="sElapsed">–</b></div>
      <div><small>Tables</small><b id="sTables">–</b></div>
      <div><small>Current</small><b id="sCurrent" class="trunc">–</b></div>
    </div>
    <div id="banner" class="alert" hidden></div>
    <div class="row controls">
      <button class="btn primary" id="btnStart">Start</button>
      <button class="btn" id="btnPause" disabled>Pause</button>
      <button class="btn" id="btnResume" disabled>Resume</button>
      <button class="btn danger" id="btnCancel" disabled>Cancel</button>
    </div>
    <details><summary>Per-table progress</summary><div id="perTable" class="tablelist"></div></details>
    <div id="log" class="log"></div>
    <p class="muted small">Sizes are estimated from table statistics. Keep this tab open while transferring; if it is closed, reopen and press Resume &ndash; work continues from the last committed batch.</p>
  </section>
  <section class="card" id="diffCard">
    <div class="row between">
      <h2>Compare databases <span class="muted">(local vs remote)</span></h2>
      <div class="row">
        <label class="inline"><input type="checkbox" id="diffCounts"> Include row counts</label>
        <button class="btn" id="btnDiff">Compare</button>
      </div>
    </div>
    <p class="muted small">Finds tables, views, columns, indexes, foreign keys, triggers, routines and events that are missing on one side or defined differently.</p>
    <div id="diffOut"></div>
  </section>
</main>
<script>window.MIG = { csrf: <?= json_encode(Auth::csrf()) ?> };</script>
<script src="assets/app.js"></script>
<?php endif; ?>
</body>
</html>
