# FilaWarden WordPress + Drupal port

Laravel Filament packages are untouched. This port mirrors their activities and the slate operations shell.

## Source of truth
- Core: skillbobby/Spiggle-FilaWarden-Core
- Pro: skillbobby/Spiggle-FilaWarden-Advanced

## Repos
- Spiggle-FilaWarden-WordPress-Core (MIT)
- Spiggle-FilaWarden-WordPress-Advanced (commercial, requires Core)
- Spiggle-FilaWarden-Drupal-Core (MIT)
- Spiggle-FilaWarden-Drupal-Advanced (commercial, requires Core)

## Same activities
Core: executive 5-vector dashboard, 12-point deployment auditor, /proc infrastructure telemetry, queue monitor with retry/forget, scheduler heartbeat, database footprint and top tables, error-log tail, SSL sentinel, risk-file scanner (.sql/.sh/.zip/.tar/.env).
Pro: secret regex scanner, public .env/.git exposure audit, HTTP header compliance, APM p50/p95/p99 + RPM, slow query registry, incident board (triggered → investigating → resolved), Slack/Discord/custom webhooks, rule-based one-click remediation.

## Look
Fixed full-viewport shell: #0f172a sidebar, #f1f5f9 canvas, white rounded cards, emerald/amber/red badges, monospace live feed, dark-mode toggle. Same nav labels as the Filament pages.

## Platform mapping
- Laravel queues → WordPress cron/Action Scheduler, Drupal Queue API
- Laravel scheduler → WP-Cron / Drupal cron + heartbeat option/state
- laravel.log → debug.log / Drupal watchdog + PHP error log
- config/route cache checks → object cache, aggregation, opcode cache, salts, trusted hosts
