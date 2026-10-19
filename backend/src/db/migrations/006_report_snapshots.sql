-- Store a point-in-time report snapshot so exports remain stable if analysis
-- presentation code changes later. Existing reports can be populated on export.
alter table reports add column report_data jsonb;
alter table reports add constraint reports_data_object
  check (report_data is null or jsonb_typeof(report_data) = 'object');
