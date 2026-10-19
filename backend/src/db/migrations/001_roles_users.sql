-- Shared trigger: keep updated_at current
create or replace function set_updated_at() returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create table roles (
  id          smallint generated always as identity primary key,
  name        varchar(30) not null unique check (name ~ '^[a-z_]+$'),
  description text not null,
  created_at  timestamptz not null default now()
);

insert into roles (name, description) values
  ('super_admin', 'Full access, including role management and user deletion'),
  ('admin',       'Manage users, scans, audit logs and threat intelligence'),
  ('analyst',     'Review scans and manage threat intelligence'),
  ('user',        'Standard user: scan URLs and files, view own history');

create table users (
  id             integer generated always as identity primary key,
  role_id        smallint not null references roles(id) on delete restrict,
  name           varchar(80) not null,
  email          varchar(254) not null,
  password_hash  text not null,
  status         varchar(20) not null default 'Active',
  last_login_at  timestamptz,
  last_active_at timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  constraint users_name_len       check (length(btrim(name)) >= 2),
  constraint users_email_lower    check (email = lower(email)),
  constraint users_email_format   check (email ~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'),
  constraint users_status_valid   check (status in ('Active','Pending','Suspended','Inactive')),
  -- Only bcrypt hashes are accepted, so a plaintext password can never be stored
  constraint users_password_bcrypt check (password_hash ~ '^[$]2[aby][$][0-9]{2}[$][./A-Za-z0-9]{53}$')
);
create unique index users_email_key on users (email);
create index users_role_idx   on users (role_id);
create index users_status_idx on users (status);
create trigger users_set_updated_at before update on users
  for each row execute function set_updated_at();
