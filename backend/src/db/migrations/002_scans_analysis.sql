-- A user performs many scans; each scan has at most one record in every 1:1 analysis table
create table scans (
  id           integer generated always as identity primary key,
  user_id      integer not null references users(id) on delete cascade,
  target_url   text not null,
  host         varchar(255) not null,
  scan_type    varchar(10) not null default 'URL',
  status       varchar(12) not null default 'Completed',
  reviewed_by  integer references users(id) on delete set null,
  reviewed_at  timestamptz,
  created_at   timestamptz not null default now(),
  completed_at timestamptz,
  updated_at   timestamptz not null default now(),
  constraint scans_url_len  check (length(target_url) between 4 and 2048),
  constraint scans_type     check (scan_type in ('URL')),
  constraint scans_status   check (status in ('Running','Completed','Reviewed','Failed'))
);
create index scans_user_created_idx on scans (user_id, created_at desc);
create index scans_status_idx       on scans (status);
create index scans_host_idx         on scans (host);
create index scans_created_idx      on scans (created_at desc);
create trigger scans_set_updated_at before update on scans
  for each row execute function set_updated_at();

-- ML result (1:1)
create table scan_results (
  scan_id       integer primary key references scans(id) on delete cascade,
  prediction    varchar(12) not null,
  probability   numeric(5,2) not null,
  confidence    numeric(5,2) not null,
  model_name    varchar(40) not null,
  model_version varchar(20) not null,
  top_features  jsonb not null default '[]'::jsonb,
  created_at    timestamptz not null default now(),
  constraint scan_results_prediction  check (prediction in ('Phishing','Legitimate')),
  constraint scan_results_probability check (probability between 0 and 100),
  constraint scan_results_confidence  check (confidence between 0 and 100),
  constraint scan_results_features    check (jsonb_typeof(top_features) = 'array')
);
create index scan_results_prediction_idx on scan_results (prediction);

create table url_indicators (
  scan_id            integer primary key references scans(id) on delete cascade,
  url_length         integer not null,
  subdomain_count    integer not null default 0,
  special_char_count integer not null default 0,
  is_ip_based        boolean not null default false,
  has_encoding       boolean not null default false,
  uses_shortener     boolean not null default false,
  suspicious_keywords text[] not null default '{}',
  redirect_count     integer not null default 0,
  created_at         timestamptz not null default now(),
  constraint url_ind_nonneg check (url_length > 0 and subdomain_count >= 0 and special_char_count >= 0 and redirect_count >= 0)
);

create table domain_indicators (
  scan_id         integer primary key references scans(id) on delete cascade,
  domain          varchar(255) not null,
  domain_age_days integer,
  registrar       varchar(80),
  dns_resolves    boolean not null default true,
  nameservers     text[] not null default '{}',
  reputation      varchar(10) not null default 'Unknown',
  whois_privacy   boolean not null default false,
  registered_at   date,
  created_at      timestamptz not null default now(),
  constraint domain_ind_age        check (domain_age_days is null or domain_age_days >= 0),
  constraint domain_ind_reputation check (reputation in ('Good','Neutral','Poor','Unknown'))
);
create index domain_indicators_domain_idx on domain_indicators (domain);

create table tls_analysis (
  scan_id           integer primary key references scans(id) on delete cascade,
  https_enabled     boolean not null,
  certificate_valid boolean,
  issuer            varchar(120),
  issued_at         timestamptz,
  expires_at        timestamptz,
  hostname_match    boolean,
  tls_version       varchar(10),
  weak_cipher       boolean not null default false,
  created_at        timestamptz not null default now(),
  constraint tls_validity_window check (issued_at is null or expires_at is null or expires_at > issued_at)
);

create table website_analysis (
  scan_id               integer primary key references scans(id) on delete cascade,
  has_login_form        boolean not null default false,
  has_password_field    boolean not null default false,
  external_form_action  varchar(255),
  iframe_count          integer not null default 0,
  hidden_element_count  integer not null default 0,
  has_suspicious_scripts boolean not null default false,
  has_auto_download     boolean not null default false,
  redirect_count        integer not null default 0,
  created_at            timestamptz not null default now(),
  constraint website_nonneg check (iframe_count >= 0 and hidden_element_count >= 0 and redirect_count >= 0)
);

-- Zero or more impersonated brands per scan
create table brand_matches (
  id           integer generated always as identity primary key,
  scan_id      integer not null references scans(id) on delete cascade,
  brand        varchar(60) not null,
  similarity   numeric(5,2) not null,
  levenshtein  numeric(5,2) not null,
  jaro_winkler numeric(5,2) not null,
  ngram        numeric(5,2) not null,
  created_at   timestamptz not null default now(),
  constraint brand_matches_unique unique (scan_id, brand),
  constraint brand_matches_range check (similarity between 0 and 100 and levenshtein between 0 and 100 and jaro_winkler between 0 and 100 and ngram between 0 and 100)
);
create index brand_matches_scan_idx  on brand_matches (scan_id);
create index brand_matches_brand_idx on brand_matches (brand);

-- One row per intelligence provider consulted for the scan
create table threat_intelligence_results (
  id                 integer generated always as identity primary key,
  scan_id            integer not null references scans(id) on delete cascade,
  provider           varchar(60) not null,
  reputation         varchar(12) not null,
  is_known_malicious boolean not null default false,
  threat_category    varchar(40),
  detail             varchar(80),
  checked_at         timestamptz not null default now(),
  constraint ti_results_unique     unique (scan_id, provider),
  constraint ti_results_reputation check (reputation in ('Malicious','Suspicious','Clean','Unknown'))
);
create index ti_results_scan_idx     on threat_intelligence_results (scan_id);
create index ti_results_provider_idx on threat_intelligence_results (provider, reputation);

-- level and threat_level are derived from score, so they can never disagree with it
create table risk_assessments (
  scan_id      integer primary key references scans(id) on delete cascade,
  score        smallint not null,
  level        text generated always as (
                 case when score < 20 then 'Very Low' when score < 40 then 'Low'
                      when score < 60 then 'Medium'   when score < 80 then 'High' else 'Critical' end) stored,
  threat_level text generated always as (
                 case when score < 20 then 'Minimal' when score < 40 then 'Low'
                      when score < 60 then 'Moderate' when score < 80 then 'Elevated' else 'Severe' end) stored,
  category     varchar(40) not null,
  summary      text,
  indicators   jsonb not null default '[]'::jsonb,
  created_at   timestamptz not null default now(),
  constraint risk_score_range     check (score between 0 and 100),
  constraint risk_indicators_type check (jsonb_typeof(indicators) = 'array')
);
create index risk_assessments_score_idx on risk_assessments (score);
create index risk_assessments_level_idx on risk_assessments (level);

create table recommendations (
  id          integer generated always as identity primary key,
  scan_id     integer not null references scans(id) on delete cascade,
  icon        varchar(16),
  title       varchar(120) not null,
  description text not null,
  priority    varchar(10) not null default 'Medium',
  sort_order  smallint not null default 0,
  created_at  timestamptz not null default now(),
  constraint recommendations_priority check (priority in ('High','Medium','Low'))
);
create index recommendations_scan_idx on recommendations (scan_id, sort_order);

-- Read model used by lists, dashboards and admin screens
create view scan_summaries as
select s.id, s.user_id, u.email, s.target_url as target, s.host, s.scan_type as type, s.status,
       s.created_at, s.completed_at,
       coalesce(ra.score, 0)::int            as score,
       coalesce(ra.level, 'Very Low')        as level,
       coalesce(ra.category, 'Unknown')      as category,
       coalesce(sr.prediction, 'Legitimate') as prediction,
       coalesce(sr.confidence, 0)            as confidence
from scans s
join users u on u.id = s.user_id
left join risk_assessments ra on ra.scan_id = s.id
left join scan_results sr     on sr.scan_id = s.id;
