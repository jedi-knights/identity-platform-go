-- Initial entitlements catalog seed (E3-S3 / #156).
-- Idempotent: every INSERT uses ON CONFLICT (unique key) to upsert or
-- ON CONFLICT DO NOTHING for join rows. Safe to re-run.
--
-- Categories:
--   app          — user-facing product surfaces (Touchline, Scout Sleuth)
--   mcp-server   — MCP server instances (one row per jk-mcp-* server)
--   mcp-tool     — individual tools exposed by an MCP server
--   data-source  — upstream data feeds MCP servers pull from
--   feature      — capabilities inside an app (match review, HD replay, seats)
--
-- ADR references:
--   ADR-0028 — catalog lives here; bundles/plans model per decisions 3/4
--   ADR-0027 — quotas/seats enforced from plan.metadata; this seed sets
--              plans.match_quota + plans.seat_allowance to match

BEGIN;

-- =============================================================================
-- RESOURCES
-- =============================================================================

INSERT INTO resources (code, display_name, category, description) VALUES
  -- Apps
  ('app:touchline',            'Touchline',              'app',
   'Match review / scouting app for coaches and clubs.'),
  ('app:scout-sleuth',         'Scout Sleuth',           'app',
   'Player-discovery app. Placeholder resource — product not yet in market.'),

  -- MCP servers
  ('mcp:jk-mcp-ecnl',          'ECNL MCP server',        'mcp-server',
   'MCP server exposing ECNL (girls & boys club soccer) data.'),
  ('mcp:jk-mcp-ncaa-soccer',   'NCAA Soccer MCP server', 'mcp-server',
   'MCP server exposing NCAA soccer data (D1/D2/D3, women & men).'),
  ('mcp:jk-mcp-nfl',           'NFL MCP server',         'mcp-server',
   'MCP server exposing NFL data.'),
  ('mcp:jk-mcp-nwsl',          'NWSL MCP server',        'mcp-server',
   'MCP server exposing NWSL (National Women''s Soccer League) data.'),

  -- MCP tools — ECNL (from the exposed tool set)
  ('tool:jk-mcp-ecnl:get_clubs',        'ECNL: get_clubs',        'mcp-tool',
   'List ECNL clubs.'),
  ('tool:jk-mcp-ecnl:get_teams',        'ECNL: get_teams',        'mcp-tool',
   'List teams in an ECNL club.'),
  ('tool:jk-mcp-ecnl:get_schedule',     'ECNL: get_schedule',     'mcp-tool',
   'Fetch schedule for an ECNL team.'),
  ('tool:jk-mcp-ecnl:get_standings',    'ECNL: get_standings',    'mcp-tool',
   'Fetch ECNL league standings.'),
  ('tool:jk-mcp-ecnl:get_rpi',          'ECNL: get_rpi',          'mcp-tool',
   'RPI (rating percentage index) for ECNL teams.'),
  ('tool:jk-mcp-ecnl:get_results',      'ECNL: get_results',      'mcp-tool',
   'Fetch ECNL match results.'),

  -- MCP tools — NWSL (from the exposed tool set)
  ('tool:jk-mcp-nwsl:get_standings',    'NWSL: get_standings',    'mcp-tool',
   'Fetch NWSL league standings.'),
  ('tool:jk-mcp-nwsl:get_scoreboard',   'NWSL: get_scoreboard',   'mcp-tool',
   'Fetch NWSL scoreboard.'),
  ('tool:jk-mcp-nwsl:get_team_schedule','NWSL: get_team_schedule','mcp-tool',
   'Fetch schedule for an NWSL team.'),
  ('tool:jk-mcp-nwsl:get_roster',       'NWSL: get_roster',       'mcp-tool',
   'Fetch NWSL team roster.'),
  ('tool:jk-mcp-nwsl:get_match_details','NWSL: get_match_details','mcp-tool',
   'Fetch a specific NWSL match.'),

  -- MCP tools — NCAA / NFL (placeholders, actual tool sets not enumerated here)
  ('tool:jk-mcp-ncaa-soccer:get_rpi',   'NCAA Soccer: get_rpi',   'mcp-tool',
   'RPI for NCAA soccer teams. Placeholder — confirm tool inventory.'),
  ('tool:jk-mcp-nfl:get_scoreboard',    'NFL: get_scoreboard',    'mcp-tool',
   'Fetch NFL scoreboard. Placeholder — confirm tool inventory.'),

  -- Data sources (placeholders — real feed list to be confirmed)
  ('data:sports-reference',    'Sports Reference feed',  'data-source',
   'Placeholder for the sports-reference.com data feed.'),
  ('data:espn-scoreboards',    'ESPN scoreboards',       'data-source',
   'Placeholder for ESPN scoreboards feed.'),

  -- App features (Touchline capabilities gated by tier)
  ('feature:touchline:match_review',    'Touchline: match review',    'feature',
   'Ability to create and view match-review sessions.'),
  ('feature:touchline:hd_replays',      'Touchline: HD replays',      'feature',
   'Access to HD-quality replay downloads.'),
  ('feature:touchline:multi_seat',      'Touchline: multi-seat',      'feature',
   'Ability to add teammates as additional seats under one account.'),
  ('feature:touchline:pdf_export',      'Touchline: PDF export',      'feature',
   'Export match reviews as PDF reports.')
ON CONFLICT (code) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      category     = EXCLUDED.category,
      description  = EXCLUDED.description,
      updated_at   = now();

-- =============================================================================
-- BUNDLES
-- =============================================================================

INSERT INTO bundles (code, display_name, description) VALUES
  ('bundle-free',
     'Free',
     'Baseline capabilities on the free tier: Touchline match review with quota, ECNL public data.'),
  ('bundle-touchline-coach',
     'Touchline Coach',
     'Full Touchline coach tier — unlimited match reviews, HD replays, PDF export, single seat.'),
  ('bundle-touchline-club',
     'Touchline Club',
     'Everything Coach has + multi-seat + all sport MCP access. Sold with a 10-seat allowance.'),
  ('bundle-ncaa-d1-women',
     'NCAA D1 Women',
     'NCAA Soccer MCP access scoped to Division-I women. Sold separately as a scoping add-on.'),
  ('bundle-nwsl-full',
     'NWSL Full',
     'Unrestricted access to NWSL MCP tools. Sold separately as an add-on.'),
  ('bundle-youth-free-tier',
     'Youth Free Tier',
     'ECNL youth-only free access — public standings and schedules only, no RPI, no downloads.')
ON CONFLICT (code) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      description  = EXCLUDED.description,
      updated_at   = now();

-- =============================================================================
-- BUNDLE ↔ RESOURCE mappings
-- =============================================================================

-- Helper CTE approach for readability: resolve codes -> ids, insert join rows.

-- bundle-free grants: Touchline app, match_review feature (with quota),
-- ECNL server, and the public-data ECNL tools.
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, c.constraints::jsonb
FROM bundles b
JOIN (VALUES
  ('bundle-free', 'app:touchline',                       '{}'),
  ('bundle-free', 'feature:touchline:match_review',      '{"monthly_quota": 3}'),
  ('bundle-free', 'mcp:jk-mcp-ecnl',                     '{}'),
  ('bundle-free', 'tool:jk-mcp-ecnl:get_clubs',          '{}'),
  ('bundle-free', 'tool:jk-mcp-ecnl:get_teams',          '{}'),
  ('bundle-free', 'tool:jk-mcp-ecnl:get_schedule',       '{}'),
  ('bundle-free', 'tool:jk-mcp-ecnl:get_standings',      '{}'),
  ('bundle-free', 'tool:jk-mcp-ecnl:get_results',        '{}')
) AS c(bundle_code, resource_code, constraints) ON c.bundle_code = b.code
JOIN resources r ON r.code = c.resource_code
ON CONFLICT (bundle_id, resource_id) DO UPDATE
  SET constraints = EXCLUDED.constraints;

-- bundle-touchline-coach: unlimited Touchline features, HD replays, PDF export,
-- + everything free grants (composed at plan level via multiple bundles).
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, c.constraints::jsonb
FROM bundles b
JOIN (VALUES
  ('bundle-touchline-coach', 'app:touchline',                    '{}'),
  ('bundle-touchline-coach', 'feature:touchline:match_review',   '{"monthly_quota": null}'),
  ('bundle-touchline-coach', 'feature:touchline:hd_replays',     '{}'),
  ('bundle-touchline-coach', 'feature:touchline:pdf_export',     '{}'),
  ('bundle-touchline-coach', 'tool:jk-mcp-ecnl:get_rpi',         '{}'),
  ('bundle-touchline-coach', 'tool:jk-mcp-nwsl:get_standings',   '{}'),
  ('bundle-touchline-coach', 'tool:jk-mcp-nwsl:get_scoreboard',  '{}')
) AS c(bundle_code, resource_code, constraints) ON c.bundle_code = b.code
JOIN resources r ON r.code = c.resource_code
ON CONFLICT (bundle_id, resource_id) DO UPDATE
  SET constraints = EXCLUDED.constraints;

-- bundle-touchline-club: multi-seat + all MCP access, on top of Coach's set.
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, c.constraints::jsonb
FROM bundles b
JOIN (VALUES
  ('bundle-touchline-club', 'feature:touchline:multi_seat',           '{"seat_allowance": 10}'),
  ('bundle-touchline-club', 'mcp:jk-mcp-nwsl',                        '{}'),
  ('bundle-touchline-club', 'mcp:jk-mcp-ncaa-soccer',                 '{}'),
  ('bundle-touchline-club', 'mcp:jk-mcp-nfl',                         '{}'),
  ('bundle-touchline-club', 'tool:jk-mcp-nwsl:get_team_schedule',     '{}'),
  ('bundle-touchline-club', 'tool:jk-mcp-nwsl:get_roster',            '{}'),
  ('bundle-touchline-club', 'tool:jk-mcp-nwsl:get_match_details',     '{}'),
  ('bundle-touchline-club', 'tool:jk-mcp-ncaa-soccer:get_rpi',        '{}'),
  ('bundle-touchline-club', 'tool:jk-mcp-nfl:get_scoreboard',         '{}')
) AS c(bundle_code, resource_code, constraints) ON c.bundle_code = b.code
JOIN resources r ON r.code = c.resource_code
ON CONFLICT (bundle_id, resource_id) DO UPDATE
  SET constraints = EXCLUDED.constraints;

-- Add-on bundle: NCAA D1 Women — the NCAA Soccer MCP scoped to D1 women.
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, c.constraints::jsonb
FROM bundles b
JOIN (VALUES
  ('bundle-ncaa-d1-women', 'mcp:jk-mcp-ncaa-soccer',           '{"division": "d1", "gender": "women"}'),
  ('bundle-ncaa-d1-women', 'tool:jk-mcp-ncaa-soccer:get_rpi',  '{"division": "d1", "gender": "women"}')
) AS c(bundle_code, resource_code, constraints) ON c.bundle_code = b.code
JOIN resources r ON r.code = c.resource_code
ON CONFLICT (bundle_id, resource_id) DO UPDATE
  SET constraints = EXCLUDED.constraints;

-- Add-on bundle: NWSL Full — everything the NWSL MCP exposes.
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, '{}'::jsonb
FROM bundles b
JOIN resources r
  ON r.code IN (
    'mcp:jk-mcp-nwsl',
    'tool:jk-mcp-nwsl:get_standings',
    'tool:jk-mcp-nwsl:get_scoreboard',
    'tool:jk-mcp-nwsl:get_team_schedule',
    'tool:jk-mcp-nwsl:get_roster',
    'tool:jk-mcp-nwsl:get_match_details'
  )
WHERE b.code = 'bundle-nwsl-full'
ON CONFLICT (bundle_id, resource_id) DO NOTHING;

-- Youth-Free-Tier bundle: ECNL public standings + schedule, no RPI.
INSERT INTO bundle_resources (bundle_id, resource_id, constraints)
SELECT b.id, r.id, '{}'::jsonb
FROM bundles b
JOIN resources r
  ON r.code IN (
    'mcp:jk-mcp-ecnl',
    'tool:jk-mcp-ecnl:get_clubs',
    'tool:jk-mcp-ecnl:get_teams',
    'tool:jk-mcp-ecnl:get_schedule',
    'tool:jk-mcp-ecnl:get_standings'
  )
WHERE b.code = 'bundle-youth-free-tier'
ON CONFLICT (bundle_id, resource_id) DO NOTHING;

-- =============================================================================
-- PLANS — mirrors Lago plan.code from infra/lago/plans/*.json
-- =============================================================================

INSERT INTO plans (code, display_name, tier, seat_allowance, match_quota) VALUES
  ('touchline-free',   'Touchline Free',   'free',   1, 3),
  ('touchline-coach',  'Touchline Coach',  'coach',  1, NULL),
  ('touchline-club',   'Touchline Club',   'club',  10, NULL)
ON CONFLICT (code) DO UPDATE
  SET display_name   = EXCLUDED.display_name,
      tier           = EXCLUDED.tier,
      seat_allowance = EXCLUDED.seat_allowance,
      match_quota    = EXCLUDED.match_quota,
      updated_at     = now();

-- =============================================================================
-- PLAN ↔ BUNDLE mappings
-- =============================================================================
--
-- Compositional model: higher tiers inherit everything lower tiers grant,
-- expressed by mapping the same base bundles. This keeps the "what does
-- Coach get?" answer as a UNION over its bundles' resources.
--
-- NCAA-D1-Women and NWSL-Full are add-on bundles — not attached to any
-- plan by default. Sold separately in a future flow (Epic 4+).

INSERT INTO plan_bundles (plan_id, bundle_id)
SELECT p.id, b.id
FROM plans p
JOIN (VALUES
  ('touchline-free',   'bundle-free'),
  ('touchline-free',   'bundle-youth-free-tier'),
  ('touchline-coach',  'bundle-free'),
  ('touchline-coach',  'bundle-touchline-coach'),
  ('touchline-club',   'bundle-free'),
  ('touchline-club',   'bundle-touchline-coach'),
  ('touchline-club',   'bundle-touchline-club')
) AS m(plan_code, bundle_code) ON m.plan_code = p.code
JOIN bundles b ON b.code = m.bundle_code
ON CONFLICT (plan_id, bundle_id) DO NOTHING;

COMMIT;
