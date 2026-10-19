create table reports (
  id           integer generated always as identity primary key,
  scan_id      integer not null references scans(id) on delete cascade,
  user_id      integer not null references users(id) on delete cascade,
  format       varchar(10) not null default 'pdf',
  file_size_kb integer not null default 120,
  created_at   timestamptz not null default now(),
  constraint reports_format check (format in ('pdf','csv','json')),
  constraint reports_size   check (file_size_kb > 0)
);
create index reports_user_created_idx on reports (user_id, created_at desc);
create index reports_scan_idx         on reports (scan_id);

create table threat_feeds (
  id             integer generated always as identity primary key,
  name           varchar(60) not null unique,
  status         varchar(20) not null default 'Operational',
  enabled        boolean not null default true,
  coverage       varchar(60),
  last_synced_at timestamptz not null default now(),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  constraint threat_feeds_status check (status in ('Operational','Degraded','Offline'))
);
create trigger threat_feeds_set_updated_at before update on threat_feeds
  for each row execute function set_updated_at();

-- Admin-managed blocklist
create table threat_indicators (
  id         integer generated always as identity primary key,
  indicator  varchar(2048) not null,
  type       varchar(10) not null,
  category   varchar(40) not null,
  severity   varchar(10) not null,
  source     varchar(40) not null default 'Manual',
  status     varchar(10) not null default 'Active',
  added_by   integer references users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint threat_ind_unique   unique (indicator),
  constraint threat_ind_lower    check (indicator = lower(indicator)),
  constraint threat_ind_type     check (type in ('URL','Domain','IP','Hash')),
  constraint threat_ind_severity check (severity in ('High','Medium','Low')),
  constraint threat_ind_status   check (status in ('Active','Pending','Disabled'))
);
create index threat_ind_status_idx  on threat_indicators (status);
create index threat_ind_created_idx on threat_indicators (created_at desc);
create trigger threat_ind_set_updated_at before update on threat_indicators
  for each row execute function set_updated_at();

create table attachment_analyses (
  id         integer generated always as identity primary key,
  user_id    integer not null references users(id) on delete cascade,
  filename   text not null,
  size_bytes bigint not null,
  sha256     char(64) not null,
  risk_score smallint not null,
  result     jsonb not null,
  created_at timestamptz not null default now(),
  constraint attach_size   check (size_bytes > 0),
  constraint attach_sha    check (sha256 ~ '^[a-f0-9]{64}$'),
  constraint attach_score  check (risk_score between 0 and 100)
);
create index attach_user_created_idx on attachment_analyses (user_id, created_at desc);
create index attach_sha_idx          on attachment_analyses (sha256);

create table audit_logs (
  id            bigint generated always as identity primary key,
  user_id       integer references users(id) on delete set null,
  user_email    varchar(254),
  action        varchar(40) not null,
  resource_type varchar(30),
  resource_id   varchar(40),
  ip            inet,
  result        varchar(10) not null default 'Success',
  detail        text,
  created_at    timestamptz not null default now(),
  constraint audit_result check (result in ('Success','Failure','Blocked'))
);
create index audit_created_idx on audit_logs (created_at desc);
create index audit_user_idx    on audit_logs (user_id);
create index audit_action_idx  on audit_logs (action);
