import time
import uuid

import redis


_SEMAPHORE_KEY = "filetrace:analysis_semaphore"
_SEMAPHORE_TOKEN_KEY_PREFIX = "filetrace:analysis_semaphore:token:"


def acquire_semaphore_slot(
    r: redis.Redis,
    *,
    limit: int,
    ttl_seconds: int,
    poll_seconds: float = 1.0,
) -> str:
    token = uuid.uuid4().hex

    lua = r.register_script(
        """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
        local token = ARGV[4]
        local token_prefix = ARGV[5]

        -- cleanup expired
        redis.call('ZREMRANGEBYSCORE', key, '-inf', now)

        -- cleanup orphan tokens (leftovers from crashed/restarted workers)
        local members = redis.call('ZRANGE', key, 0, -1)
        for i = 1, #members do
            local t = members[i]
            local tok_key = token_prefix .. t
            if redis.call('EXISTS', tok_key) == 0 then
                redis.call('ZREM', key, t)
            end
        end

        local count = redis.call('ZCARD', key)
        if count < limit then
            redis.call('ZADD', key, now + ttl, token)
            redis.call('SET', token_prefix .. token, '1', 'EX', ttl)
            return token
        end
        return ''
        """
    )

    while True:
        now = time.time()
        acquired = lua(keys=[_SEMAPHORE_KEY], args=[now, int(limit), int(ttl_seconds), token, _SEMAPHORE_TOKEN_KEY_PREFIX])
        if acquired:
            try:
                acquired_str = acquired.decode("utf-8") if isinstance(acquired, (bytes, bytearray)) else str(acquired)
            except Exception:
                acquired_str = str(acquired)
            if acquired_str:
                return acquired_str
        time.sleep(poll_seconds)


def release_semaphore_slot(r: redis.Redis, token: str) -> None:
    try:
        r.zrem(_SEMAPHORE_KEY, token)
        r.delete(_SEMAPHORE_TOKEN_KEY_PREFIX + token)
    except Exception:
        pass


def refresh_semaphore_slot(r: redis.Redis, token: str, *, ttl_seconds: int) -> None:
    try:
        now = time.time()
        r.zadd(_SEMAPHORE_KEY, {token: now + int(ttl_seconds)})
        r.expire(_SEMAPHORE_TOKEN_KEY_PREFIX + token, int(ttl_seconds))
    except Exception:
        pass
