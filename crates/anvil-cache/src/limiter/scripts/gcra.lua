-- GCRA request-rate check for one key (anvil-cache RedisLimiter::check).
--
-- Mirrors governor 0.10 exactly (pinned by the limiter contract suite):
--   tat defaults to now; tau = T * (burst - 1); allow iff now >= tat - tau; then
--   tat = max(tat, now) + T. A denial changes nothing.
--
-- KEYS[1] = bucket key
-- ARGV[1] = now (microseconds, from the core clock; never Redis TIME)
-- ARGV[2] = T, the emission interval (microseconds)
-- ARGV[3] = tau, the burst tolerance (microseconds)
-- Returns {1, 0} (allow) or {0, retry_after_us} (deny).
--
-- Numbers are written with %.0f: Lua's default number formatting (%.14g) would round
-- microsecond timestamps.

local now = tonumber(ARGV[1])
local t = tonumber(ARGV[2])
local tau = tonumber(ARGV[3])

local tat = tonumber(redis.call('GET', KEYS[1])) or now
local earliest = tat - tau
if now < earliest then
  return {0, earliest - now}
end

local nxt = math.max(tat, now) + t
-- The state is indistinguishable from a fresh key once tat <= now; the expiry only bounds
-- memory (in Redis time), so it gets a one-second margin for clock skew between nodes.
local ttl_ms = math.ceil((nxt - now) / 1000) + 1000
redis.call('SET', KEYS[1], string.format('%.0f', nxt), 'PX', string.format('%.0f', ttl_ms))
return {1, 0}
