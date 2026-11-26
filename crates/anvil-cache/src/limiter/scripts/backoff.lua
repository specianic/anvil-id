-- Progressive backoff and the two-tier brute-force gate (anvil-cache RedisLimiter).
--
-- One atomic script for the backoff store; ARGV[1] selects the operation, so each trait method
-- is exactly one script invocation. Mirrors limiter/backoff.rs (pinned by the contract suite).
--
-- Entry (hash): f = failures, lu = locked_until, lf = last_failure, ws = loose window start,
-- lc = failures in the loose window. Times are microseconds from the core clock (never Redis
-- TIME). An entry idle for `idle` (2 * cap) since its last failure is treated as absent; the
-- key expiry only bounds memory.
--
-- Common ARGV: [1] op, [2] now, [3] idle, [4] window (loose tier, one hour).
--   fail  KEYS[1]=key            ARGV[5]=loose (1|0) [6]=free_attempts [7]=base [8]=cap
--         -> {failures, locked_for_us}
--   get   KEYS[1]=key            -> locked_for_us (0 = not locked)
--   clear KEYS[1]=key            -> 1
--   gate  KEYS[1]=strict KEYS[2]=loose  ARGV[5]=loose threshold
--         -> {0, 0} allow | {1, retry_after_us} strict lock | {2, 0} loose over threshold

local op = ARGV[1]
local now = tonumber(ARGV[2])
local idle = tonumber(ARGV[3])
local window = tonumber(ARGV[4])

local function fmt(n)
  return string.format('%.0f', n)
end

local function live(key)
  local v = redis.call('HMGET', key, 'f', 'lu', 'lf', 'ws', 'lc')
  local lf = tonumber(v[3])
  if not lf then
    return nil
  end
  if now - lf >= idle then
    redis.call('DEL', key)
    return nil
  end
  return {
    f = tonumber(v[1]) or 0,
    lu = tonumber(v[2]),
    lf = lf,
    ws = tonumber(v[4]) or now,
    lc = tonumber(v[5]) or 0,
  }
end

local function remaining(lu)
  if lu and lu > now then
    return lu - now
  end
  return 0
end

if op == 'fail' then
  local loose = ARGV[5] == '1'
  local free = tonumber(ARGV[6])
  local base = tonumber(ARGV[7])
  local cap = tonumber(ARGV[8])
  local e = live(KEYS[1]) or { f = 0, lu = nil, lf = now, ws = now, lc = 0 }
  if now - e.ws >= window then
    e.ws = now
    e.lc = 0
  end
  e.lc = math.min(e.lc + 1, 4294967295)
  e.lf = now
  if loose then
    -- The loose tier is never locked: it only escalates to CAPTCHA or a delay.
    e.f = e.lc
  else
    e.f = math.min(e.f + 1, 4294967295)
    local over = e.f - free - 1
    if over >= 0 then
      local factor = 4294967295
      if over < 32 then
        factor = 2 ^ over
      end
      e.lu = now + math.min(base * factor, cap)
    else
      e.lu = nil
    end
  end
  redis.call('HSET', KEYS[1], 'f', fmt(e.f), 'lf', fmt(e.lf), 'ws', fmt(e.ws), 'lc', fmt(e.lc))
  if e.lu then
    redis.call('HSET', KEYS[1], 'lu', fmt(e.lu))
  else
    redis.call('HDEL', KEYS[1], 'lu')
  end
  redis.call('PEXPIRE', KEYS[1], fmt(math.ceil(idle / 1000) + 1000))
  return {e.f, remaining(e.lu)}
elseif op == 'get' then
  local e = live(KEYS[1])
  if not e then
    return 0
  end
  return remaining(e.lu)
elseif op == 'clear' then
  redis.call('DEL', KEYS[1])
  return 1
elseif op == 'gate' then
  local threshold = tonumber(ARGV[5])
  local s = live(KEYS[1])
  if s then
    local r = remaining(s.lu)
    if r > 0 then
      return {1, r}
    end
  end
  local l = live(KEYS[2])
  if l and now - l.ws < window and l.lc >= threshold then
    return {2, 0}
  end
  return {0, 0}
end

return redis.error_reply('unknown backoff operation')
