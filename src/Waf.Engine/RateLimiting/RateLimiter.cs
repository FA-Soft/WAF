using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Waf.Core.Configuration;
using Waf.Core.Net;

namespace Waf.Engine.RateLimiting;

/// <summary>Outcome of a rate-limit check.</summary>
public enum RateLimitOutcome
{
    /// <summary>Within all limits.</summary>
    Allowed,

    /// <summary>Over a limit: reject with 429.</summary>
    Limited,

    /// <summary>Over a limit in detection-only mode: log, but let the request through.</summary>
    WouldLimit,
}

/// <summary>Result of <see cref="RateLimiter.Check"/>.</summary>
public sealed record RateLimitDecision(RateLimitOutcome Outcome, string? RuleName, TimeSpan RetryAfter)
{
    /// <summary>Shared instance for requests within all limits.</summary>
    public static RateLimitDecision Allowed { get; } = new(RateLimitOutcome.Allowed, null, TimeSpan.Zero);

    public bool IsLimited => Outcome == RateLimitOutcome.Limited;
}

/// <summary>
/// Applies the configured rate limits with sliding-window counters kept in a memory-bounded table.
/// Thread-safe; one instance per configuration.
/// </summary>
/// <remarks>
/// <para>
/// Sliding window: the count is the current fixed window plus the previous window weighted by how much of
/// it still overlaps. Every request is counted, including rejected ones.
/// </para>
/// <para>
/// Memory bound: at most <see cref="Capacity"/> counters exist. When the table is full, counters whose
/// windows have expired are removed first; if that is not enough, the counters with the fewest requests
/// (then the least recently used) are removed until 10% is free. A flood of requests from many new
/// addresses therefore evicts other low-count entries, not the counters of clients near their limit.
/// </para>
/// </remarks>
public sealed class RateLimiter
{
    private readonly CompiledLimit[] _limits;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<CounterKey, Counter> _counters = new();
    private readonly Lock _evictionLock = new();
    private int _count;

    public RateLimiter(GatewayConfiguration configuration, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var errors = GatewayConfigurationValidator.Validate(configuration);
        if (errors.Count > 0)
        {
            throw new ArgumentException("The configuration is not valid: " + string.Join(" ", errors), nameof(configuration));
        }

        _time = timeProvider ?? TimeProvider.System;
        Capacity = configuration.Settings.RateLimitMaxTrackedClients;
        _limits = [.. configuration.RateLimits
            .Select((limit, index) => (limit, index))
            .Where(x => x.limit.Enabled)
            .Select(x => new CompiledLimit(x.index, x.limit, configuration.Settings.DetectionOnly))];
    }

    /// <summary>Maximum number of counters kept in memory.</summary>
    public int Capacity { get; }

    /// <summary>Number of counters currently in memory.</summary>
    public int TrackedCount => Volatile.Read(ref _count);

    /// <summary>True when at least one limit is enabled.</summary>
    public bool HasLimits => _limits.Length > 0;

    /// <summary>Counts the request against every applicable limit and reports whether it is over one.</summary>
    public RateLimitDecision Check(IWafRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (_limits.Length == 0)
        {
            return RateLimitDecision.Allowed;
        }

        var now = _time.GetUtcNow().UtcTicks;
        RateLimitDecision? wouldLimit = null;
        RateLimitDecision? limited = null;

        foreach (var limit in _limits)
        {
            if (!limit.AppliesTo(request))
            {
                continue;
            }

            var counter = GetCounter(limit.KeyFor(request), now);
            if (!counter.TryAcquire(now, limit.WindowTicks, limit.PermitLimit, out var retryAfter))
            {
                var decision = new RateLimitDecision(
                    limit.DetectionOnly ? RateLimitOutcome.WouldLimit : RateLimitOutcome.Limited, limit.Name, retryAfter);

                if (decision.IsLimited)
                {
                    limited ??= decision;
                }
                else
                {
                    wouldLimit ??= decision;
                }
            }
        }

        return limited ?? wouldLimit ?? RateLimitDecision.Allowed;
    }

    private Counter GetCounter(CounterKey key, long now)
    {
        if (_counters.TryGetValue(key, out var existing))
        {
            return existing;
        }

        if (Volatile.Read(ref _count) >= Capacity)
        {
            Evict(now);
        }

        var created = new Counter(now);
        var counter = _counters.GetOrAdd(key, created);
        if (ReferenceEquals(counter, created))
        {
            Interlocked.Increment(ref _count);
        }

        return counter;
    }

    private void Evict(long now)
    {
        lock (_evictionLock)
        {
            if (Volatile.Read(ref _count) < Capacity)
            {
                return; // another thread already made room
            }

            // 1. Counters whose windows have fully expired hold no information.
            foreach (var (key, counter) in _counters)
            {
                if (counter.IsExpired(now, _limits[LimitIndex(key)].WindowTicks))
                {
                    Remove(key);
                }
            }

            // 2. Still too full: drop the lowest counts first, least recently used among equals, down to 90%.
            var target = Capacity - Math.Max(1, Capacity / 10);
            var excess = Volatile.Read(ref _count) - target;
            if (excess <= 0)
            {
                return;
            }

            var victims = _counters
                .Select(entry => (entry.Key, Load: entry.Value.Load(now, _limits[LimitIndex(entry.Key)].WindowTicks), entry.Value.LastSeen))
                .OrderBy(entry => entry.Load)
                .ThenBy(entry => entry.LastSeen)
                .Take(excess)
                .Select(entry => entry.Key)
                .ToList();

            foreach (var key in victims)
            {
                Remove(key);
            }
        }
    }

    private int LimitIndex(CounterKey key) => Array.FindIndex(_limits, l => l.ConfigIndex == key.Limit);

    private void Remove(CounterKey key)
    {
        if (_counters.TryRemove(key, out _))
        {
            Interlocked.Decrement(ref _count);
        }
    }

    /// <summary>Counter key: limit, client network and/or route depending on the limit's key type.</summary>
    private readonly record struct CounterKey(int Limit, UInt128 Client, string? Route);

    private sealed class CompiledLimit
    {
        private readonly CompiledCondition[] _conditions;
        private readonly HashSet<string>? _routes;
        private readonly RateLimitKey _key;

        public CompiledLimit(int configIndex, RateLimitRule rule, bool globalDetectionOnly)
        {
            ConfigIndex = configIndex;
            Name = rule.Name;
            PermitLimit = rule.PermitLimit;
            WindowTicks = TimeSpan.FromSeconds(rule.WindowSeconds).Ticks;
            DetectionOnly = rule.DetectionOnly || globalDetectionOnly;
            _key = rule.Key;
            _conditions = [.. rule.Conditions.Select(CompiledCondition.Compile)];
            _routes = rule.Routes.Count == 0 ? null : new HashSet<string>(rule.Routes, StringComparer.OrdinalIgnoreCase);
        }

        public int ConfigIndex { get; }

        public string Name { get; }

        public int PermitLimit { get; }

        public long WindowTicks { get; }

        public bool DetectionOnly { get; }

        public bool AppliesTo(IWafRequest request)
        {
            if (_routes is not null && (request.RouteName is null || !_routes.Contains(request.RouteName)))
            {
                return false;
            }

            foreach (var condition in _conditions)
            {
                if (!condition.Matches(request))
                {
                    return false;
                }
            }

            return true;
        }

        public CounterKey KeyFor(IWafRequest request) => _key switch
        {
            RateLimitKey.ClientIp => new CounterKey(ConfigIndex, ClientNetwork(request.ClientIp), null),
            RateLimitKey.ClientIpAndRoute => new CounterKey(ConfigIndex, ClientNetwork(request.ClientIp), request.RouteName),
            _ => new CounterKey(ConfigIndex, UInt128.Zero, request.RouteName),
        };
    }

    /// <summary>
    /// Client identity for counting: the IPv4 address, or the /64 network of an IPv6 address
    /// (one host can use any address in its /64).
    /// </summary>
    internal static UInt128 ClientNetwork(IPAddress address)
    {
        var ip = ClientIpResolver.Normalize(address);
        Span<byte> bytes = stackalloc byte[16];
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // Store IPv4 as ::ffff:a.b.c.d so it can never collide with an IPv6 /64.
            bytes[10] = 0xFF;
            bytes[11] = 0xFF;
            ip.TryWriteBytes(bytes[12..], out _);
        }
        else
        {
            ip.TryWriteBytes(bytes, out _);
            bytes[8..].Clear();
        }

        return new UInt128(
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]));
    }

    /// <summary>Sliding-window counter for one key.</summary>
    private sealed class Counter(long now)
    {
        private readonly Lock _lock = new();
        private long _window = long.MinValue;
        private int _current;
        private int _previous;

        public long LastSeen { get; private set; } = now;

        public bool TryAcquire(long now, long windowTicks, int permitLimit, out TimeSpan retryAfter)
        {
            lock (_lock)
            {
                Advance(now, windowTicks);
                LastSeen = now;

                var estimate = Estimate(now, windowTicks);
                _current++;

                if (estimate < permitLimit)
                {
                    retryAfter = TimeSpan.Zero;
                    return true;
                }

                // Until the current window ends; at least one second.
                var remaining = windowTicks - (now % windowTicks);
                retryAfter = TimeSpan.FromSeconds(Math.Max(1, Math.Ceiling(TimeSpan.FromTicks(remaining).TotalSeconds)));
                return false;
            }
        }

        public double Load(long now, long windowTicks)
        {
            lock (_lock)
            {
                Advance(now, windowTicks);
                return Estimate(now, windowTicks);
            }
        }

        public bool IsExpired(long now, long windowTicks)
        {
            lock (_lock)
            {
                return now / windowTicks > _window + 1;
            }
        }

        private void Advance(long now, long windowTicks)
        {
            var window = now / windowTicks;
            if (window == _window)
            {
                return;
            }

            _previous = window == _window + 1 ? _current : 0;
            _current = 0;
            _window = window;
        }

        private double Estimate(long now, long windowTicks)
        {
            var elapsed = (double)(now % windowTicks) / windowTicks;
            return (_previous * (1 - elapsed)) + _current;
        }
    }
}
