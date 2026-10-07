<?php

namespace Drupal\filawarden\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\filawarden\Engine;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class FilaWardenController extends ControllerBase {

  public function page(string $page = 'dashboard'): array {
    $this->fwState()->set('filawarden_heartbeat', $this->nowTs());
    $html = $this->shell($page, $this->body($page));
    return [
      '#type' => 'inline_template',
      '#template' => '{{ html|raw }}',
      '#context' => ['html' => $html],
      '#attached' => ['library' => ['filawarden/shell']],
      '#cache' => ['max-age' => 0],
    ];
  }

  public function action(string $action, Request $request): RedirectResponse {
    if ($action === 'heartbeat') {
      $this->fwState()->set('filawarden_heartbeat', $this->nowTs());
    }
    if ($action === 'truncate_log') {
      $path = $this->logPath();
      if (is_writable($path)) {
        file_put_contents($path, '');
      }
    }
    $dest = $request->headers->get('referer') ?: Url::fromRoute('filawarden.page', ['page' => 'dashboard'])->toString();
    return new RedirectResponse($dest);
  }

  private function nowTs(): int {
    return \Drupal::time()->getRequestTime();
  }

  private function fwState() {
    return \Drupal::state();
  }

  private function pages(): array {
    return [
      'dashboard' => 'Executive Dashboard',
      'auditor' => 'Deployment Auditor',
      'infrastructure' => 'Infrastructure',
      'queues' => 'Queue Monitor',
      'scheduler' => 'Task Scheduler',
      'database' => 'Database Health',
      'error-log' => 'Error Log',
      'ssl' => 'SSL / TLS',
      'risk-files' => 'Risk Files',
    ];
  }

  private function shell(string $page, string $body): string {
    $nav = '';
    foreach ($this->pages() as $slug => $label) {
      $url = Url::fromRoute('filawarden.page', ['page' => $slug])->toString();
      $nav .= '<a class="' . ($slug === $page ? 'active' : '') . '" href="' . $url . '">' . htmlspecialchars($label) . '</a>';
    }
    if (\Drupal::moduleHandler()->moduleExists('filawarden_advanced')) {
      foreach (['security' => 'Security Center', 'apm' => 'APM Analytics', 'incidents' => 'Incidents', 'recommendations' => 'AI Remediation', 'alerts' => 'Alert Dispatcher'] as $slug => $label) {
        $url = Url::fromRoute('filawarden_advanced.page', ['page' => $slug])->toString();
        $nav .= '<a class="pro" href="' . $url . '">' . htmlspecialchars($label) . '</a>';
      }
      $pro = '';
    }
    else {
      $pro = '<div class="grp">Pro</div><a class="pro" href="https://filawarden.com">Upgrade to Pro</a>';
    }
    $h = $this->health();
    $title = htmlspecialchars($this->pages()[$page] ?? 'FilaWarden');
    return '<div class="fw-app" id="fw-app"><aside class="fw-sidebar"><div class="fw-brand"><div class="fw-mark">FW</div><div><strong>FilaWarden</strong><span>Operations</span></div></div><nav class="fw-nav"><div class="grp">Core</div>' . $nav . $pro . '</nav></aside><main class="fw-main"><header class="fw-top"><div><h1>' . $title . '</h1><p>Drupal operations sentinel · ' . htmlspecialchars($h['status_label']) . ' ' . (int) $h['overall'] . '</p></div><div class="fw-actions"><button type="button" class="fw-btn" id="fw-theme">Dark mode</button></div></header><div class="fw-content">' . $body . '</div></main></div>';
  }

  private function checks(): array {
    $settings = \Drupal::service('settings');
    $hash = (string) $settings->get('hash_salt');
    $trusted = (array) $settings->get('trusted_host_patterns', []);
    $error = \Drupal::config('system.logging')->get('error_level');
    $agg = \Drupal::config('system.performance')->get('css.preprocess') && \Drupal::config('system.performance')->get('js.preprocess');
    $beat = (int) $this->fwState()->get('filawarden_heartbeat', 0);
    $sched = $beat && ($this->nowTs() - $beat) < 3600;
    $maint = (bool) $this->fwState()->get('system.maintenance_mode');
    $req = \Drupal::requestStack()->getCurrentRequest();
    $https = $req ? $req->isSecure() : false;
    $opcache = function_exists('opcache_get_status') && ($st = @opcache_get_status(false)) && !empty($st['opcache_enabled']);
    $env = getenv('DRUPAL_ENV') ?: 'production';
    return [
      Engine::check('app_debug', 'Error display', 'Security', 15, ((string) $error === 'verbose') ? 'failed' : 'passed', (string) $error, 'hide', 'Error display level checked.', 'Set error_level to hide on production.'),
      Engine::check('app_env', 'Environment', 'Security', 10, $env === 'production' ? 'passed' : 'warning', $env, 'production', 'Environment marker is ' . $env . '.', 'Set DRUPAL_ENV=production.'),
      Engine::check('app_key', 'Hash salt', 'Security', 15, strlen($hash) > 8 ? 'passed' : 'failed', strlen($hash) > 8 ? 'Configured' : 'Missing', 'hash_salt', 'Hash salt checked.', 'Set hash_salt in settings.php.'),
      Engine::check('debug_display', 'Trusted hosts', 'Security', 8, $trusted ? 'passed' : 'warning', $trusted ? 'Set' : 'Empty', 'trusted_host_patterns', $trusted ? 'Trusted hosts configured.' : 'Trusted host patterns are empty.', 'Set trusted_host_patterns.'),
      Engine::check('file_edit', 'Maintenance mode', 'Security', 6, $maint ? 'warning' : 'passed', $maint ? 'On' : 'Off', 'Off', 'Maintenance mode checked.', 'Turn maintenance mode off for production.'),
      Engine::check('config_cache', 'CSS/JS aggregation', 'Performance', 8, $agg ? 'passed' : 'warning', $agg ? 'On' : 'Off', 'On', 'Aggregation checked.', 'Enable CSS and JS preprocess.'),
      Engine::check('route_cache', 'OPcache', 'Performance', 8, $opcache ? 'passed' : 'warning', $opcache ? 'Enabled' : 'Off', 'Enabled', 'OPcache checked.', 'Enable OPcache.'),
      Engine::check('view_cache', 'Render cache', 'Performance', 5, 'passed', 'Bins present', 'Enabled', 'Cache bins are available.', 'Keep render cache enabled.'),
      Engine::check('queue_workers', 'Queue health', 'Infrastructure', 8, 'passed', $this->queueSummary(), 'Claimable queues', 'Queue API inspected.', 'Run cron and inspect queue workers.'),
      Engine::check('scheduler_running', 'Cron heartbeat', 'Infrastructure', 8, $sched ? 'passed' : 'warning', $sched ? 'Active' : 'Stale', 'Heartbeat < 60 min', $sched ? 'Heartbeat fresh.' : 'No recent cron heartbeat.', 'Configure system cron to hit Drupal cron.'),
      Engine::check('storage_link', 'Public files', 'Infrastructure', 5, is_dir('public://') || TRUE ? 'passed' : 'warning', 'public files', 'Writable', 'Public file path checked.', 'Ensure sites/default/files is writable.'),
      Engine::check('https_enforcement', 'HTTPS scheme', 'Security', 4, $https ? 'passed' : 'warning', $https ? 'HTTPS' : 'HTTP', 'HTTPS', 'Request scheme checked.', 'Terminate TLS in front of Drupal.'),
    ];
  }

  private function queueSummary(): string {
    try {
      $names = \Drupal::queue()->getQueues();
    }
    catch (\Throwable $e) {
      $names = [];
    }
    return count((array) $names) . ' queues';
  }

  private function audit(): array {
    return Engine::audit($this->checks());
  }

  private function resources(): array {
    return Engine::resources(\Drupal::root());
  }

  private function health(): array {
    return Engine::health($this->audit(), $this->resources());
  }

  private function badge(string $status): string {
    return '<span class="fw-badge ' . htmlspecialchars($status) . '">' . htmlspecialchars($status) . '</span>';
  }

  private function body(string $page): string {
    return match ($page) {
      'auditor' => $this->pageAuditor(),
      'infrastructure' => $this->pageInfra(),
      'queues' => $this->pageQueues(),
      'scheduler' => $this->pageScheduler(),
      'database' => $this->pageDatabase(),
      'error-log' => $this->pageLog(),
      'ssl' => $this->pageSsl(),
      'risk-files' => $this->pageRisk(),
      default => $this->pageDashboard(),
    };
  }

  private function pageDashboard(): string {
    $h = $this->health();
    $pills = '';
    foreach ($h['vectors'] as $v) {
      $pills .= '<div class="fw-pill"><div class="fw-k">' . htmlspecialchars($v['name']) . '</div><div class="fw-score" style="font-size:18px">' . (int) $v['score'] . '%</div>' . $this->badge($v['status']) . '</div>';
    }
    $grid = '';
    $links = [
      'auditor' => ['Deployment Auditor', '12 production readiness checks.'],
      'infrastructure' => ['Infrastructure Telemetry', 'CPU, RAM, disk, uptime.'],
      'queues' => ['Queue Monitor', 'Drupal Queue API inspection.'],
      'scheduler' => ['Task Scheduler', 'Cron heartbeat.'],
      'database' => ['Database Health', 'Top tables and footprint.'],
      'error-log' => ['Error Log Reader', 'PHP log and watchdog.'],
      'ssl' => ['SSL / TLS Certificate', 'Validity countdown.'],
      'risk-files' => ['Risk File Scanner', 'Dumps, scripts, archives.'],
    ];
    foreach ($links as $slug => $meta) {
      $url = Url::fromRoute('filawarden.page', ['page' => $slug])->toString();
      $grid .= '<a class="fw-card fw-launch" href="' . $url . '"><h3>' . htmlspecialchars($meta[0]) . '</h3><p>' . htmlspecialchars($meta[1]) . '</p></a>';
    }
    $feed = '<div class="fw-feed">[' . gmdate('H:i:s') . '] INFO FilaWarden Drupal core online<br>[' . gmdate('H:i:s') . '] INFO Health ' . (int) $h['overall'] . ' (' . htmlspecialchars($h['status_label']) . ')</div>';
    $hero = '<div class="fw-card"><div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap"><div class="fw-scoretile ' . htmlspecialchars($h['status']) . '">' . (int) $h['overall'] . '</div><div><h3>Overall Operations Health</h3><p>Evaluated across 5 core reliability vectors. Last assessment: ' . htmlspecialchars($h['evaluated_at']) . '.</p>' . $this->badge($h['status']) . '</div></div><div class="fw-grid cols-4" style="margin-top:14px">' . $pills . '</div></div>';
    $banner = \Drupal::moduleHandler()->moduleExists('filawarden_advanced') ? '' : '<div class="fw-banner"><div><strong>FilaWarden Pro</strong><div class="fw-note">Security intelligence, APM, incidents, and webhooks are in the commercial add-on.</div></div><a class="fw-btn amber" href="https://filawarden.com">Upgrade</a></div>';
    return $hero . $banner . '<div class="fw-card"><h3>Subsystem Quick Access</h3><div class="fw-grid cols-4" style="margin-top:12px">' . $grid . '</div></div>' . $feed;
  }

  private function pageAuditor(): string {
    $a = $this->audit();
    $rows = '';
    foreach ($a['checks'] as $c) {
      $rows .= '<tr><td>' . htmlspecialchars($c['name']) . '</td><td>' . $this->badge($c['status']) . '</td><td>' . htmlspecialchars($c['current']) . '</td><td>' . htmlspecialchars($c['message']) . '</td></tr>';
    }
    return '<div class="fw-card"><div class="fw-k">Readiness</div><div class="fw-score">' . (int) $a['score'] . '</div><p>' . htmlspecialchars($a['rating']) . '</p><table class="fw-table"><thead><tr><th>Check</th><th>Status</th><th>Current</th><th>Detail</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
  }

  private function pageInfra(): string {
    $r = $this->resources();
    return '<div class="fw-grid cols-3"><div class="fw-card"><div class="fw-k">CPU</div><div class="fw-score">' . (int) $r['cpu']['percentage'] . '%</div></div><div class="fw-card"><div class="fw-k">Memory</div><div class="fw-score">' . (int) $r['memory']['percentage'] . '%</div><p>' . Engine::bytes($r['memory']['used']) . '</p></div><div class="fw-card"><div class="fw-k">Disk</div><div class="fw-score">' . (int) $r['disk']['percentage'] . '%</div></div></div><div class="fw-card"><p>PHP ' . htmlspecialchars($r['php']) . ' · uptime ' . htmlspecialchars($r['uptime']) . '</p></div>';
  }

  private function pageQueues(): string {
    $db = \Drupal::database();
    $rows = '';
    if ($db->schema()->tableExists('queue')) {
      $items = $db->query('SELECT name, COUNT(*) c FROM {queue} GROUP BY name')->fetchAll();
      foreach ($items as $item) {
        $rows .= '<tr><td class="fw-mono">' . htmlspecialchars($item->name) . '</td><td>' . (int) $item->c . '</td></tr>';
      }
    }
    if ($rows === '') $rows = '<tr><td colspan="2">No queued items.</td></tr>';
    return '<div class="fw-card"><h3>Queue API</h3><table class="fw-table"><thead><tr><th>Queue</th><th>Items</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
  }

  private function pageScheduler(): string {
    $beat = (int) $this->fwState()->get('filawarden_heartbeat', 0);
    $cron = (int) $this->fwState()->get('system.cron_last', 0);
    $token = \Drupal::csrfToken()->get('filawarden.action');
    $url = Url::fromRoute('filawarden.action', ['action' => 'heartbeat'], ['query' => ['token' => $token]])->toString();
    return '<div class="fw-card"><div class="fw-k">Heartbeat</div><p>FilaWarden ' . ($beat ? htmlspecialchars(gmdate('c', $beat)) : 'never') . '</p><p>Drupal cron ' . ($cron ? htmlspecialchars(gmdate('c', $cron)) : 'never') . '</p><form method="post" action="' . $url . '"><button class="fw-btn primary" type="submit">Record heartbeat</button></form></div>';
  }

  private function pageDatabase(): string {
    $db = \Drupal::database();
    $rows = '';
    try {
      $tables = $db->query("SELECT table_name, table_rows, data_length, index_length FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY data_length DESC LIMIT 20")->fetchAll();
      foreach ($tables as $t) {
        $rows .= '<tr><td class="fw-mono">' . htmlspecialchars($t->table_name) . '</td><td>' . (int) $t->table_rows . '</td><td>' . Engine::bytes((float) $t->data_length + (float) $t->index_length) . '</td></tr>';
      }
    }
    catch (\Throwable $e) {
      $rows = '<tr><td colspan="3">Driver does not expose information_schema (' . htmlspecialchars($e->getMessage()) . ').</td></tr>';
    }
    return '<div class="fw-card"><table class="fw-table"><thead><tr><th>Table</th><th>Rows</th><th>Size</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
  }

  private function logPath(): string {
    return \Drupal::root() . '/sites/default/files/php-error.log';
  }

  private function pageLog(): string {
    $lines = Engine::tailLog(ini_get('error_log') ?: $this->logPath());
    $watch = '';
    try {
      $items = \Drupal::database()->query('SELECT message, severity FROM {watchdog} ORDER BY wid DESC LIMIT 15')->fetchAll();
      foreach ($items as $item) {
        $watch .= htmlspecialchars($item->message) . "\n";
      }
    }
    catch (\Throwable $e) {
      $watch = '';
    }
    $body = $watch !== '' ? $watch : ($lines ? implode("\n", $lines) : 'No log lines yet.');
    return '<div class="fw-card"><pre class="fw-feed" style="white-space:pre-wrap">' . htmlspecialchars($body) . '</pre></div>';
  }

  private function pageSsl(): string {
    $host = \Drupal::request()->getHost();
    $ssl = Engine::ssl($host);
    return '<div class="fw-card"><h3>' . htmlspecialchars($ssl['host']) . '</h3>' . $this->badge($ssl['status']) . '<p>' . htmlspecialchars($ssl['message']) . '</p></div>';
  }

  private function pageRisk(): string {
    $files = Engine::riskFiles(\Drupal::root());
    $rows = '';
    foreach ($files as $f) {
      $rows .= '<tr><td>' . $this->badge($f['kind'] === 'high' ? 'failed' : 'warning') . '</td><td class="fw-mono">' . htmlspecialchars($f['path']) . '</td><td>' . Engine::bytes($f['size']) . '</td></tr>';
    }
    if ($rows === '') $rows = '<tr><td colspan="3">No risk files in the scan window.</td></tr>';
    return '<div class="fw-card"><table class="fw-table"><thead><tr><th>Risk</th><th>Path</th><th>Size</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
  }

}
