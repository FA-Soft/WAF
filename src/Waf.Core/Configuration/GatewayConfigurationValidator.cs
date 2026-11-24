using System.Text.RegularExpressions;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Core.Configuration;

/// <summary>
/// Validates a complete <see cref="GatewayConfiguration"/> and returns plain-language errors.
/// An empty result means the configuration is valid.
/// </summary>
public static class GatewayConfigurationValidator
{
    /// <summary>Longest regular expression accepted in a rule condition.</summary>
    public const int MaxRegexLength = 1000;

    public static IReadOnlyList<string> Validate(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var errors = new List<string>();

        if (configuration.SchemaVersion != GatewayConfiguration.CurrentSchemaVersion)
        {
            errors.Add($"SchemaVersion {configuration.SchemaVersion} is not supported (expected {GatewayConfiguration.CurrentSchemaVersion}).");
        }

        ValidateSettings(configuration.Settings, errors);
        errors.AddRange(ProxyRouteValidator.Validate([.. configuration.Routes]));
        TargetResolver.Validate(configuration, errors);

        var routeNames = new HashSet<string>(configuration.Routes.Select(r => r.Name), StringComparer.OrdinalIgnoreCase);
        ValidateRules(configuration.Rules, routeNames, errors);
        ValidateRateLimits(configuration.RateLimits, routeNames, errors);
        ValidateAttackDetection(configuration.Settings?.AttackDetection, routeNames, errors);
        ValidateLogRetention(configuration.Settings?.LogRetention, errors);
        ValidateCertificates(configuration.Certificates, configuration.Settings, errors);
        ValidateHttps(configuration, errors);

        return errors;
    }

    /// <summary>Largest permit limit accepted for a rate limit.</summary>
    public const int MaxPermitLimit = 1_000_000;

    /// <summary>Longest rate-limit window: one day.</summary>
    public const int MaxWindowSeconds = 86_400;

    /// <summary>Largest body part that can be inspected: 10 MB.</summary>
    public const int MaxInspectedBodyBytes = 10 * 1024 * 1024;

    private static void ValidateLogRetention(LogRetentionSettings? retention, List<string> errors)
    {
        if (retention is null)
        {
            errors.Add("Settings.LogRetention is missing.");
            return;
        }

        if (retention.MaxAgeDays is < 0 or > LogRetentionSettings.MaxMaxAgeDays)
        {
            errors.Add($"Settings.LogRetention.MaxAgeDays must be between 0 (no age limit) and {LogRetentionSettings.MaxMaxAgeDays} (was {retention.MaxAgeDays}).");
        }

        if (retention.MaxDatabaseSizeMb is < LogRetentionSettings.MinDatabaseSizeMb or > LogRetentionSettings.MaxDatabaseSizeLimitMb)
        {
            errors.Add($"Settings.LogRetention.MaxDatabaseSizeMb must be between {LogRetentionSettings.MinDatabaseSizeMb} and {LogRetentionSettings.MaxDatabaseSizeLimitMb} (was {retention.MaxDatabaseSizeMb}).");
        }
    }

    private static void ValidateAttackDetection(AttackDetectionSettings? detection, HashSet<string> routeNames, List<string> errors)
    {
        if (detection is null)
        {
            errors.Add("Settings.AttackDetection is missing.");
            return;
        }

        if (detection.MaxBodyBytes is < 1 or > MaxInspectedBodyBytes)
        {
            errors.Add($"Settings.AttackDetection.MaxBodyBytes must be between 1 and {MaxInspectedBodyBytes} (10 MB; was {detection.MaxBodyBytes}).");
        }

        for (var i = 0; i < detection.Exclusions.Count; i++)
        {
            var exclusion = detection.Exclusions[i];
            var label = $"Detection exclusion #{i + 1}";

            if (string.IsNullOrEmpty(exclusion.PathPrefix) || exclusion.PathPrefix[0] != '/')
            {
                errors.Add($"{label}: the path prefix must start with '/' (was '{exclusion.PathPrefix}').");
            }

            foreach (var route in exclusion.Routes)
            {
                if (!routeNames.Contains(route))
                {
                    errors.Add($"{label}: route '{route}' does not exist.");
                }
            }

            foreach (var category in exclusion.Categories)
            {
                if (!Enum.IsDefined(category))
                {
                    errors.Add($"{label}: unknown category.");
                }
            }
        }
    }

    private static void ValidateRateLimits(IList<RateLimitRule> limits, HashSet<string> routeNames, List<string> errors)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < limits.Count; i++)
        {
            var limit = limits[i];
            var label = string.IsNullOrWhiteSpace(limit.Name) ? $"Rate limit #{i + 1}" : $"Rate limit '{limit.Name}'";

            if (string.IsNullOrWhiteSpace(limit.Name))
            {
                errors.Add($"{label}: a name is required.");
            }
            else if (!ProxyRouteValidator.IsValidName(limit.Name))
            {
                errors.Add($"{label}: the name may only contain letters, digits, '-', '_' and '.'.");
            }
            else if (!names.Add(limit.Name))
            {
                errors.Add($"{label}: the name is used by more than one rate limit.");
            }

            if (limit.PermitLimit is < 1 or > MaxPermitLimit)
            {
                errors.Add($"{label}: PermitLimit must be between 1 and {MaxPermitLimit} (was {limit.PermitLimit}).");
            }

            if (limit.WindowSeconds is < 1 or > MaxWindowSeconds)
            {
                errors.Add($"{label}: WindowSeconds must be between 1 and {MaxWindowSeconds} (one day; was {limit.WindowSeconds}).");
            }

            if (!Enum.IsDefined(limit.Key))
            {
                errors.Add($"{label}: Key must be ClientIp, ClientIpAndRoute or Route.");
            }

            foreach (var route in limit.Routes)
            {
                if (!routeNames.Contains(route))
                {
                    errors.Add($"{label}: route '{route}' does not exist.");
                }
            }

            for (var c = 0; c < limit.Conditions.Count; c++)
            {
                var where = limit.Conditions.Count == 1 ? label : $"{label}, condition #{c + 1}";
                ValidateCondition(where, limit.Conditions[c], errors);
            }
        }
    }

    private static void ValidateSettings(GatewaySettings? settings, List<string> errors)
    {
        if (settings is null)
        {
            errors.Add("Settings are missing.");
            return;
        }

        foreach (var proxy in settings.TrustedProxies)
        {
            if (!StrictCidr.TryParse(proxy, out _, out var reason))
            {
                errors.Add($"Trusted proxy '{proxy}': {reason}.");
            }
        }

        if (settings.RateLimitMaxTrackedClients is < 1_000 or > 10_000_000)
        {
            errors.Add($"Settings.RateLimitMaxTrackedClients must be between 1000 and 10000000 (was {settings.RateLimitMaxTrackedClients}).");
        }
    }

    private static void ValidateRules(IList<WafRule> rules, HashSet<string> routeNames, List<string> errors)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rules.Count; i++)
        {
            var rule = rules[i];
            var label = string.IsNullOrWhiteSpace(rule.Name) ? $"Rule #{i + 1}" : $"Rule '{rule.Name}'";

            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                errors.Add($"{label}: a name is required.");
            }
            else if (!ProxyRouteValidator.IsValidName(rule.Name))
            {
                errors.Add($"{label}: the name may only contain letters, digits, '-', '_' and '.'.");
            }
            else if (!names.Add(rule.Name))
            {
                errors.Add($"{label}: the name is used by more than one rule.");
            }

            if (!Enum.IsDefined(rule.Action))
            {
                errors.Add($"{label}: action must be Allow, Block or LogOnly.");
            }

            if (rule.Priority < 0)
            {
                errors.Add($"{label}: priority must be 0 or higher (was {rule.Priority}).");
            }

            foreach (var route in rule.Routes)
            {
                if (!routeNames.Contains(route))
                {
                    errors.Add($"{label}: route '{route}' does not exist.");
                }
            }

            if (rule.Conditions.Count == 0)
            {
                errors.Add($"{label}: at least one condition is required (to match every request, use Path StartsWith '/').");
            }

            for (var c = 0; c < rule.Conditions.Count; c++)
            {
                var where = rule.Conditions.Count == 1 ? label : $"{label}, condition #{c + 1}";
                ValidateCondition(where, rule.Conditions[c], errors);
            }
        }
    }

    private static void ValidateCondition(string where, RuleCondition? condition, List<string> errors)
    {
        if (condition is null)
        {
            errors.Add($"{where}: the condition is empty.");
            return;
        }

        if (!Enum.IsDefined(condition.Field))
        {
            errors.Add($"{where}: unknown field.");
            return;
        }

        if (!Enum.IsDefined(condition.Operator))
        {
            errors.Add($"{where}: unknown operator.");
            return;
        }

        if (condition.Field == ConditionField.Header)
        {
            if (string.IsNullOrEmpty(condition.HeaderName) || !condition.HeaderName.All(IsHeaderNameChar))
            {
                errors.Add($"{where}: a valid HeaderName is required for the Header field (e.g. 'X-Api-Key').");
            }
        }
        else if (condition.HeaderName is not null)
        {
            errors.Add($"{where}: HeaderName is only used with the Header field.");
        }

        var allowed = AllowedOperators(condition.Field);
        if (!allowed.Contains(condition.Operator))
        {
            errors.Add($"{where}: operator {condition.Operator} cannot be used with {condition.Field} (use {string.Join(" or ", allowed)}).");
            return;
        }

        if (condition.Values.Count == 0)
        {
            errors.Add($"{where}: at least one value is required.");
            return;
        }

        foreach (var value in condition.Values)
        {
            ValidateValue(where, condition, value, errors);
        }
    }

    private static void ValidateValue(string where, RuleCondition condition, string? value, List<string> errors)
    {
        if (string.IsNullOrEmpty(value))
        {
            errors.Add($"{where}: values must not be empty.");
            return;
        }

        if (value == ConfigurationSecrets.Placeholder)
        {
            errors.Add($"{where}: the secret value was left out when the configuration was exported. Enter the real value.");
            return;
        }

        switch (condition.Operator)
        {
            case ConditionOperator.InCidr:
                if (!StrictCidr.TryParse(value, out _, out var reason))
                {
                    errors.Add($"{where}: '{value}': {reason}.");
                }

                break;

            case ConditionOperator.Regex:
                if (value.Length > MaxRegexLength)
                {
                    errors.Add($"{where}: the regular expression is longer than {MaxRegexLength} characters.");
                }
                else if (!IsValidRegex(value, out var problem))
                {
                    errors.Add($"{where}: '{value}' is not a supported regular expression: {problem}");
                }

                break;

            default:
                if (condition.Field == ConditionField.Method && !value.All(char.IsAsciiLetter))
                {
                    errors.Add($"{where}: '{value}' is not a valid HTTP method (use e.g. GET, POST).");
                }

                break;
        }
    }

    /// <summary>
    /// Patterns must compile for the non-backtracking engine: matching time is then linear in the input,
    /// so a pattern cannot be abused for ReDoS. Backreferences and lookarounds are not supported.
    /// </summary>
    private static bool IsValidRegex(string pattern, out string problem)
    {
        try
        {
            _ = new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            problem = string.Empty;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            problem = ex.Message;
            return false;
        }
    }

    private static ConditionOperator[] AllowedOperators(ConditionField field) => field switch
    {
        ConditionField.ClientIp => [ConditionOperator.InCidr],
        ConditionField.Method => [ConditionOperator.Equals],
        _ =>
        [
            ConditionOperator.Equals,
            ConditionOperator.StartsWith,
            ConditionOperator.EndsWith,
            ConditionOperator.Contains,
            ConditionOperator.Regex,
        ],
    };

    // RFC 9110 token characters.
    private static bool IsHeaderNameChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal);

    private static void ValidateHttps(GatewayConfiguration configuration, List<string> errors)
    {
        if (configuration.Settings?.Hsts is { } hsts)
        {
            if (hsts.MaxAgeSeconds is < 0 or > HstsSettings.MaxMaxAgeSeconds)
            {
                errors.Add($"Settings.Hsts.MaxAgeSeconds must be between 0 and {HstsSettings.MaxMaxAgeSeconds} (two years).");
            }

            if (hsts.Preload && (!hsts.IncludeSubDomains || hsts.MaxAgeSeconds < HstsSettings.DefaultMaxAgeSeconds))
            {
                errors.Add("Settings.Hsts.Preload needs IncludeSubDomains and a MaxAgeSeconds of at least 31536000 (one year).");
            }
        }

        // Redirecting to HTTPS without a certificate would send visitors to a failing connection.
        foreach (var route in configuration.Routes.Where(r => r.Enabled && r.Https?.RedirectHttp == true))
        {
            if (route.Match.Hosts.Count == 0)
            {
                errors.Add($"Route '{route.Name}': redirecting to HTTPS needs host names, each with a certificate.");
                continue;
            }

            var missing = route.Match.Hosts
                .Where(host => !configuration.Certificates.Any(c => Tls.CertificateNames.Matches(c.HostName, host)
                    || string.Equals(c.HostName, host, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (missing.Count > 0)
            {
                errors.Add($"Route '{route.Name}': redirecting to HTTPS needs a certificate for {string.Join(", ", missing)}. Add one on the Certificates page first.");
            }
        }
    }

    private static bool IsThumbprint(string value) => value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void ValidateCertificates(IList<CertificateBinding> certificates, GatewaySettings? settings, List<string> errors)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usesLetsEncrypt = false;

        for (var i = 0; i < certificates.Count; i++)
        {
            var certificate = certificates[i];
            var label = string.IsNullOrWhiteSpace(certificate.HostName) ? $"Certificate #{i + 1}" : $"Certificate '{certificate.HostName}'";

            var isWildcard = certificate.HostName?.StartsWith("*.", StringComparison.Ordinal) == true;
            var host = isWildcard ? certificate.HostName![2..] : certificate.HostName;

            if (!ProxyRouteValidator.IsValidAddress(host) || StrictIpAddress.TryParse(host, out _))
            {
                errors.Add($"{label}: a valid host name is required (e.g. 'www.example.com' or '*.example.com').");
            }
            else if (!hosts.Add(certificate.HostName!))
            {
                errors.Add($"{label}: more than one certificate is configured for this host name.");
            }

            switch (certificate.Source)
            {
                case CertificateSource.LetsEncrypt:
                    usesLetsEncrypt = true;
                    if (isWildcard)
                    {
                        errors.Add($"{label}: Let's Encrypt cannot issue wildcard certificates with HTTP validation; use your own certificate file.");
                    }

                    if (certificate.CertificatePath is not null || certificate.KeyPath is not null || certificate.Thumbprint is not null)
                    {
                        errors.Add($"{label}: CertificatePath, KeyPath and Thumbprint are not used with Source 'LetsEncrypt'.");
                    }

                    break;

                case CertificateSource.File:
                    if (string.IsNullOrWhiteSpace(certificate.CertificatePath))
                    {
                        errors.Add($"{label}: CertificatePath is required for Source 'File'.");
                    }
                    else if (certificate.KeyPath is not null
                        && certificate.CertificatePath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add($"{label}: KeyPath is only used with PEM certificates; a PFX file contains the key.");
                    }

                    if (certificate.Thumbprint is not null)
                    {
                        errors.Add($"{label}: Thumbprint is only used with Source 'Uploaded'.");
                    }

                    break;

                case CertificateSource.Uploaded:
                    if (certificate.Thumbprint is null || !IsThumbprint(certificate.Thumbprint))
                    {
                        errors.Add($"{label}: Thumbprint (the SHA-256 hash of an uploaded certificate, 64 hex digits) is required for Source 'Uploaded'.");
                    }

                    if (certificate.CertificatePath is not null || certificate.KeyPath is not null)
                    {
                        errors.Add($"{label}: CertificatePath and KeyPath are only used with Source 'File'.");
                    }

                    break;

                default:
                    errors.Add($"{label}: source must be LetsEncrypt, File or Uploaded.");
                    break;
            }
        }

        if (usesLetsEncrypt && settings?.Acme is { } acme)
        {
            if (string.IsNullOrWhiteSpace(acme.Email) || !IsPlausibleEmail(acme.Email))
            {
                errors.Add("Let's Encrypt: a valid contact e-mail is required in Settings.Acme.Email.");
            }

            if (!acme.AcceptTermsOfService)
            {
                errors.Add("Let's Encrypt: set Settings.Acme.AcceptTermsOfService to true to accept the subscriber agreement.");
            }
        }
    }

    private static bool IsPlausibleEmail(string email)
    {
        var at = email.IndexOf('@', StringComparison.Ordinal);
        return at > 0
            && at == email.LastIndexOf('@')
            && ProxyRouteValidator.IsValidAddress(email[(at + 1)..])
            && !email.Any(char.IsWhiteSpace);
    }
}
