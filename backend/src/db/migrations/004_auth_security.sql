-- Session invalidation + brute-force protection
alter table users
  add column token_version         integer not null default 0,
  add column failed_login_attempts integer not null default 0,
  add column locked_until          timestamptz,
  add constraint users_failed_attempts_nonneg check (failed_login_attempts >= 0);

-- Individually revoked tokens (logout). Rows can be purged once expires_at has passed.
create table revoked_tokens (
  jti        uuid primary key,
  user_id    integer not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  revoked_at timestamptz not null default now()
);
create index revoked_tokens_expires_idx on revoked_tokens (expires_at);
create index revoked_tokens_user_idx    on revoked_tokens (user_id);
