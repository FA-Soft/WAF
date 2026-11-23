namespace FASoft.Waf.Web;

/// <summary>
/// Brute-force protection per client address. Account lockout stops guessing one account's password, but not
/// trying many user names; so after <see cref="MaxFailures"/> failed attempts within <see cref="Window"/> from one
/// address, every sign-in attempt from it is refused for <see cref="BlockDuration"/>, whatever the account.
/// </summary>
/// <remarks>In memory: a restart clears it, which is fine, as account lockouts are stored.</remarks>
public sealed class SignInThrottle(TimeProvider time)
{
    public const int MaxFailures = 10;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan BlockDuration = TimeSpan.FromMinutes(15);

    /// <summary>At most this many addresses are tracked; beyond it the stalest are dropped.</summary>
    public const int MaxTrackedClients = 10_000;

    private readonly Dictionary<string, Client> _clients = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    /// <summary>Whether <paramref name="clientIp"/> is refused right now, and for how much longer.</summary>
    public bool IsBlocked(string clientIp, out TimeSpan remaining)
    {
        ArgumentNullException.ThrowIfNull(clientIp);

        var now = time.GetUtcNow();
        lock (_lock)
        {
            if (_clients.TryGetValue(clientIp, out var client) && client.BlockedUntil > now)
            {
                remaining = client.BlockedUntil - now;
                return true;
            }
        }

        remaining = TimeSpan.Zero;
        return false;
    }

    /// <summary>Counts a failed attempt (wrong password, unknown user name, wrong code).</summary>
    public void RecordFailure(string clientIp)
    {
        ArgumentNullException.ThrowIfNull(clientIp);

        var now = time.GetUtcNow();
        lock (_lock)
        {
            if (!_clients.TryGetValue(clientIp, out var client))
            {
                if (_clients.Count >= MaxTrackedClients)
                {
                    Prune(now);
                }

                client = new Client();
                _clients[clientIp] = client;
            }

            client.Failures.RemoveAll(t => now - t >= Window);
            client.Failures.Add(now);
            client.LastSeen = now;
            if (client.Failures.Count >= MaxFailures)
            {
                client.BlockedUntil = now + BlockDuration;
                client.Failures.Clear();
            }
        }
    }

    /// <summary>A successful sign-in forgets the earlier failures of that address.</summary>
    public void RecordSuccess(string clientIp)
    {
        ArgumentNullException.ThrowIfNull(clientIp);

        lock (_lock)
        {
            _clients.Remove(clientIp);
        }
    }

    /// <summary>Number of tracked addresses (for tests).</summary>
    internal int TrackedClients
    {
        get
        {
            lock (_lock)
            {
                return _clients.Count;
            }
        }
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var key in _clients.Where(c => c.Value.BlockedUntil <= now && now - c.Value.LastSeen >= Window).Select(c => c.Key).ToList())
        {
            _clients.Remove(key);
        }

        // Still full (an attack from very many addresses): drop the stalest unblocked ones.
        if (_clients.Count >= MaxTrackedClients)
        {
            foreach (var key in _clients.Where(c => c.Value.BlockedUntil <= now).OrderBy(c => c.Value.LastSeen)
                .Take(_clients.Count - MaxTrackedClients + 1).Select(c => c.Key).ToList())
            {
                _clients.Remove(key);
            }
        }
    }

    private sealed class Client
    {
        public List<DateTimeOffset> Failures { get; } = [];

        public DateTimeOffset LastSeen { get; set; }

        public DateTimeOffset BlockedUntil { get; set; }
    }
}
