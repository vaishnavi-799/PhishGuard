-- Full normalized report from the analysis engine + failed-scan tracking
alter table scans add column error_message text;

-- DNS may legitimately be "unknown" (network analysis skipped/failed), which is different from "does not resolve"
alter table domain_indicators alter column dns_resolves drop not null;
alter table domain_indicators alter column dns_resolves drop default;

create table analysis_reports (
  scan_id        integer primary key references scans(id) on delete cascade,
  schema_version varchar(10) not null,
  engine_version varchar(20) not null,
  duration_ms    integer,
  report         jsonb not null,
  created_at     timestamptz not null default now(),
  constraint analysis_reports_object check (jsonb_typeof(report) = 'object'),
  constraint analysis_reports_duration check (duration_ms is null or duration_ms >= 0)
);

-- append-only change (CREATE OR REPLACE VIEW can only add columns at the end)
create or replace view scan_summaries as
select s.id, s.user_id, u.email, s.target_url as target, s.host, s.scan_type as type, s.status,
       s.created_at, s.completed_at,
       coalesce(ra.score, 0)::int            as score,
       coalesce(ra.level, 'Very Low')        as level,
       coalesce(ra.category, 'Unknown')      as category,
       coalesce(sr.prediction, 'Legitimate') as prediction,
       coalesce(sr.confidence, 0)            as confidence,
       s.error_message
from scans s
join users u on u.id = s.user_id
left join risk_assessments ra on ra.scan_id = s.id
left join scan_results sr     on sr.scan_id = s.id;
