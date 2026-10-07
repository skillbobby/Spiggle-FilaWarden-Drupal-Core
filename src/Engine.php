<?php
/**
 * FilaWarden collector engine. Platform adapters pass a context array.
 */
namespace Drupal\filawarden;

class Engine {
    public static function resources(string $root): array {
        $load = [0, 0, 0];
        if (is_readable('/proc/loadavg')) {
            $parts = explode(' ', trim((string) file_get_contents('/proc/loadavg')));
            $load = [ (float) ($parts[0] ?? 0), (float) ($parts[1] ?? 0), (float) ($parts[2] ?? 0) ];
        } else {
            $avg = function_exists('sys_getloadavg') ? sys_getloadavg() : [0, 0, 0];
            $load = array_map('floatval', $avg ?: [0, 0, 0]);
        }
        $cores = 1;
        if (is_readable('/proc/cpuinfo')) {
            $cores = max(1, substr_count((string) file_get_contents('/proc/cpuinfo'), 'processor'));
        }
        $cpu = (int) min(100, round(($load[0] / $cores) * 100));
        $memTotal = 0; $memAvail = 0;
        if (is_readable('/proc/meminfo')) {
            $info = (string) file_get_contents('/proc/meminfo');
            if (preg_match('/MemTotal:\s+(\d+)/', $info, $m)) $memTotal = (int) $m[1] * 1024;
            if (preg_match('/MemAvailable:\s+(\d+)/', $info, $m)) $memAvail = (int) $m[1] * 1024;
        }
        if ($memTotal === 0) {
            $memTotal = 512 * 1024 * 1024;
            $memAvail = $memTotal - memory_get_usage(true);
        }
        $memUsed = max(0, $memTotal - $memAvail);
        $memPct = $memTotal > 0 ? (int) round(($memUsed / $memTotal) * 100) : 0;
        $diskTotal = (float) @disk_total_space($root);
        $diskFree = (float) @disk_free_space($root);
        $diskUsed = max(0, $diskTotal - $diskFree);
        $diskPct = $diskTotal > 0 ? (int) round(($diskUsed / $diskTotal) * 100) : 0;
        $uptime = 'n/a';
        if (is_readable('/proc/uptime')) {
            $sec = (int) floatval(explode(' ', trim((string) file_get_contents('/proc/uptime')))[0]);
            $uptime = sprintf('%dd %dh %dm', intdiv($sec, 86400), intdiv($sec % 86400, 3600), intdiv($sec % 3600, 60));
        }
        return [
            'cpu' => ['percentage' => $cpu, 'load' => $load, 'cores' => $cores],
            'memory' => ['percentage' => $memPct, 'used' => $memUsed, 'total' => $memTotal],
            'disk' => ['percentage' => $diskPct, 'used' => $diskUsed, 'total' => $diskTotal, 'free' => $diskFree],
            'php' => PHP_VERSION,
            'uptime' => $uptime,
        ];
    }

    public static function bytes(float $n): string {
        $u = ['B','KB','MB','GB','TB'];
        $i = 0;
        while ($n >= 1024 && $i < count($u) - 1) { $n /= 1024; $i++; }
        return number_format($n, $i ? 1 : 0) . ' ' . $u[$i];
    }

    public static function audit(array $checks): array {
        $passed = count(array_filter($checks, fn($c) => $c['status'] === 'passed'));
        $warnings = count(array_filter($checks, fn($c) => $c['status'] === 'warning'));
        $failed = count(array_filter($checks, fn($c) => $c['status'] === 'failed'));
        $max = array_sum(array_column($checks, 'weight'));
        $earned = 0;
        foreach ($checks as $c) {
            if ($c['status'] === 'passed') $earned += $c['weight'];
            elseif ($c['status'] === 'warning') $earned += $c['weight'] * 0.5;
        }
        $score = $max > 0 ? (int) round(($earned / $max) * 100) : 100;
        $rating = $score >= 90 ? 'Production Ready' : ($score >= 70 ? 'Needs Optimization' : ($score >= 50 ? 'Caution: Degraded' : 'Not Ready / High Risk'));
        return compact('score', 'rating', 'passed', 'warnings', 'failed') + [
            'total' => count($checks),
            'checks' => $checks,
            'audited_at' => gmdate('c'),
        ];
    }

    public static function check(string $id, string $name, string $category, int $weight, string $status, string $current, string $recommended, string $message, string $remediation): array {
        return compact('id', 'name', 'category', 'weight', 'status', 'current', 'recommended', 'message', 'remediation');
    }

    public static function health(array $audit, array $resources): array {
        $deploymentScore = $audit['score'];
        $cpuPenalty = max(0, $resources['cpu']['percentage'] - 50) * 1.5;
        $memPenalty = max(0, $resources['memory']['percentage'] - 60) * 1.5;
        $diskPenalty = max(0, $resources['disk']['percentage'] - 70) * 2.0;
        $infra = (int) max(10, min(100, round(100 - ($cpuPenalty + $memPenalty + $diskPenalty))));
        $relPenalty = 0;
        foreach ($audit['checks'] as $c) {
            if ($c['id'] === 'queue_workers' && $c['status'] !== 'passed') $relPenalty += 25;
            if ($c['id'] === 'scheduler_running' && $c['status'] !== 'passed') $relPenalty += 20;
        }
        $reliability = max(20, 100 - $relPenalty);
        $sec = array_values(array_filter($audit['checks'], fn($c) => $c['category'] === 'Security'));
        $perf = array_values(array_filter($audit['checks'], fn($c) => $c['category'] === 'Performance'));
        $secScore = count($sec) ? (int) round(count(array_filter($sec, fn($c) => $c['status'] === 'passed')) / count($sec) * 100) : 100;
        $perfScore = count($perf) ? (int) round(count(array_filter($perf, fn($c) => $c['status'] === 'passed')) / count($perf) * 100) : 100;
        $overall = (int) round($deploymentScore * 0.25 + $infra * 0.25 + $reliability * 0.20 + $secScore * 0.20 + $perfScore * 0.10);
        $status = $overall >= 85 ? 'healthy' : ($overall >= 65 ? 'warning' : 'danger');
        $label = $status === 'healthy' ? 'Healthy' : ($status === 'warning' ? 'Degraded' : 'Critical');
        $vec = function ($name, $score, $ok, $warn) {
            return ['name' => $name, 'score' => $score, 'status' => $score >= $ok ? 'healthy' : ($score >= $warn ? 'warning' : 'danger')];
        };
        return [
            'overall' => $overall,
            'status' => $status,
            'status_label' => $label,
            'vectors' => [
                'deployment' => $vec('Deployment Readiness', $deploymentScore, 80, 60),
                'infrastructure' => $vec('Infrastructure Headroom', $infra, 75, 50),
                'reliability' => $vec('Operational Reliability', $reliability, 80, 60),
                'security' => $vec('Security Baseline', $secScore, 80, 60),
                'performance' => $vec('Optimization & Caches', $perfScore, 80, 50),
            ],
            'evaluated_at' => gmdate('c'),
        ];
    }

    public static function riskFiles(string $root, int $limit = 40): array {
        $found = [];
        $skip = ['vendor', 'node_modules', '.git', 'core'];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        $n = 0;
        foreach ($it as $file) {
            if ($n > 8000) break;
            $n++;
            $path = $file->getPathname();
            foreach ($skip as $s) {
                if (str_contains($path, DIRECTORY_SEPARATOR . $s . DIRECTORY_SEPARATOR)) continue 2;
            }
            if (!$file->isFile()) continue;
            $ext = strtolower($file->getExtension());
            $base = strtolower($file->getFilename());
            $kind = null;
            if (in_array($ext, ['sql', 'sh'], true) || $base === '.env') $kind = 'high';
            elseif (in_array($ext, ['zip', 'tar', 'gz'], true)) $kind = 'medium';
            if (!$kind) continue;
            $found[] = ['path' => $path, 'size' => $file->getSize(), 'kind' => $kind, 'name' => $file->getFilename()];
            if (count($found) >= $limit) break;
        }
        return $found;
    }

    public static function tailLog(string $path, int $max = 80): array {
        if ($path === '' || !is_readable($path)) return [];
        $size = filesize($path);
        if ($size === false || $size === 0) return [];
        $fp = fopen($path, 'rb');
        if (!$fp) return [];
        $read = (int) min($size, 200000);
        fseek($fp, -$read, SEEK_END);
        $chunk = fread($fp, $read) ?: '';
        fclose($fp);
        $lines = array_values(array_filter(preg_split('/\r\n|\n|\r/', $chunk) ?: []));
        return array_slice($lines, -$max);
    }

    public static function parseLogLines(array $lines): array {
        $parsed = [];
        foreach ($lines as $line) {
            $level = 'info';
            if (preg_match('/\b(emergency|alert|critical|error|warning|notice|debug)\b/i', $line, $m)) {
                $level = strtolower($m[1]);
            } elseif (stripos($line, 'PHP Fatal') !== false || stripos($line, 'PHP Parse') !== false) {
                $level = 'error';
            }
            $parsed[] = ['level' => $level, 'line' => $line];
        }
        return $parsed;
    }

    public static function ssl(string $host): array {
        $host = strtolower(trim($host));
        if (in_array($host, ['localhost', '127.0.0.1', '::1', ''], true)) {
            return ['status' => 'passed', 'host' => $host ?: 'localhost', 'message' => 'Local development host.', 'days' => null, 'issuer' => 'n/a', 'subject' => 'local', 'valid_from' => null, 'valid_to' => null];
        }
        if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
            return ['status' => 'failed', 'host' => $host, 'message' => 'Host is not a DNS name.', 'days' => null, 'issuer' => 'n/a', 'subject' => '', 'valid_from' => null, 'valid_to' => null];
        }
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => true, 'verify_peer_name' => true]]);
        $client = @stream_socket_client('ssl://' . $host . ':443', $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) {
            $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false]]);
            $client = @stream_socket_client('ssl://' . $host . ':443', $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
        }
        if (!$client) return ['status' => 'failed', 'host' => $host, 'message' => $errstr ?: 'TLS handshake failed', 'days' => null, 'issuer' => 'n/a', 'subject' => '', 'valid_from' => null, 'valid_to' => null];
        $params = stream_context_get_params($client);
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate'] ?? '') ?: [];
        fclose($client);
        $to = (int) ($cert['validTo_time_t'] ?? 0);
        $from = (int) ($cert['validFrom_time_t'] ?? 0);
        $days = $to ? (int) floor(($to - time()) / 86400) : null;
        $issuer = $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? 'unknown');
        $subject = $cert['subject']['CN'] ?? $host;
        $status = 'passed';
        if ($days !== null && $days < 30) $status = 'warning';
        if ($days !== null && $days < 0) $status = 'failed';
        return ['status' => $status, 'host' => $host, 'message' => $days === null ? 'Certificate parsed' : ($days . ' days remaining'), 'days' => $days, 'issuer' => $issuer, 'subject' => $subject, 'valid_from' => $from ? gmdate('Y-m-d', $from) : null, 'valid_to' => $to ? gmdate('Y-m-d', $to) : null];
    }

    public static function percentiles(array $samples): array {
        $samples = array_values(array_filter(array_map('intval', $samples), fn($n) => $n >= 0));
        sort($samples);
        $n = count($samples);
        if ($n === 0) return ['p50' => 0, 'p95' => 0, 'p99' => 0, 'rpm' => 0, 'count' => 0];
        $pick = function ($p) use ($samples, $n) {
            $i = (int) min($n - 1, max(0, ceil($p * $n) - 1));
            return (int) round($samples[$i]);
        };
        return ['p50' => $pick(0.50), 'p95' => $pick(0.95), 'p99' => $pick(0.99), 'count' => $n, 'rpm' => $n];
    }

    public static function secretRules(): array {
        return [
            'aws_access_key' => ['title' => 'Exposed AWS Access Key ID', 'severity' => 'critical', 'regex' => '/(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)/', 'remediation' => 'Rotate the AWS IAM access key.'],
            'stripe_live_key' => ['title' => 'Exposed Stripe Live Secret Key', 'severity' => 'critical', 'regex' => '/(sk_live_[0-9a-zA-Z]{24,})/', 'remediation' => 'Roll the live secret key in Stripe.'],
            'github_pat' => ['title' => 'Exposed GitHub Personal Access Token', 'severity' => 'critical', 'regex' => '/(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/', 'remediation' => 'Revoke the token in GitHub developer settings.'],
            'slack_bot_token' => ['title' => 'Exposed Slack Bot Token', 'severity' => 'critical', 'regex' => '/(xox[baprs]-[0-9A-Za-z-]{10,})/', 'remediation' => 'Rotate the Slack token.'],
            'google_api_key' => ['title' => 'Exposed Google Cloud API Key', 'severity' => 'high', 'regex' => '/(AIza[0-9A-Za-z\-_]{35})/', 'remediation' => 'Restrict or delete the key in Google Cloud.'],
            'private_key' => ['title' => 'Exposed Private Cryptographic Key', 'severity' => 'critical', 'regex' => '/(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/', 'remediation' => 'Revoke and replace the key pair.'],
        ];
    }

    public static function secretPatterns(): array {
        $out = [];
        foreach (self::secretRules() as $id => $rule) $out[$id] = $rule['regex'];
        return $out;
    }

    public static function maskSecret(string $value): string {
        $len = strlen($value);
        if ($len <= 8) return str_repeat('*', $len);
        return substr($value, 0, 4) . str_repeat('*', max(4, $len - 8)) . substr($value, -4);
    }

    public static function scanSecrets(array $files): array {
        $findings = [];
        foreach ($files as $file) {
            if (!is_string($file) || !is_readable($file) || is_dir($file)) continue;
            $size = filesize($file);
            if ($size === false || $size === 0 || $size > 1500000) continue;
            $text = (string) file_get_contents($file);
            if ($text === '' || !mb_check_encoding($text, 'UTF-8')) continue;
            $lines = explode("\n", $text);
            foreach ($lines as $i => $line) {
                foreach (self::secretRules() as $type => $rule) {
                    if (preg_match($rule['regex'], $line, $m)) {
                        $raw = $m[1] ?? $m[0];
                        $findings[] = [
                            'type' => $type,
                            'title' => $rule['title'],
                            'severity' => $rule['severity'],
                            'file' => $file,
                            'line' => $i + 1,
                            'preview' => self::maskSecret($raw),
                            'remediation' => $rule['remediation'],
                        ];
                    }
                }
            }
        }
        return $findings;
    }

    public static function candidateFiles(string $root, int $max = 400): array {
        $found = [];
        if (!is_dir($root)) return [];
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        } catch (UnexpectedValueException) {
            return [];
        }
        $allow = ['php', 'env', 'json', 'yml', 'yaml', 'js', 'log', 'txt', 'ini'];
        foreach ($it as $file) {
            if (count($found) >= $max) break;
            $path = $file->getPathname();
            if (preg_match('#/(vendor|node_modules|\.git|core)/#', str_replace('\\', '/', $path))) continue;
            if (!$file->isFile() || $file->isLink()) continue;
            $ext = strtolower($file->getExtension());
            $name = $file->getFilename();
            if ($name === 'composer.lock' || $name === 'package-lock.json') continue;
            if ($ext === 'env' || str_starts_with($name, '.env') || in_array($ext, $allow, true)) $found[] = $path;
        }
        return $found;
    }

    public static function headerReport(array $headers): array {
        $need = ['content-security-policy' => 'CSP', 'strict-transport-security' => 'HSTS', 'x-frame-options' => 'X-Frame-Options'];
        $lower = [];
        foreach ($headers as $k => $v) $lower[strtolower((string) $k)] = $v;
        $rows = [];
        foreach ($need as $key => $label) {
            $present = isset($lower[$key]) && $lower[$key] !== '';
            $rows[] = ['id' => $key, 'label' => $label, 'status' => $present ? 'passed' : 'failed', 'current' => $present ? 'present' : 'missing'];
        }
        return $rows;
    }

    public static function validWebhook(string $url): bool {
        if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
        $parts = parse_url($url);
        return ($parts['scheme'] ?? '') === 'https' && !empty($parts['host']);
    }
}
