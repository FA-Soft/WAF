using System.Text.Json;
using System.Text.Json.Nodes;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Ai;

/// <summary>The model's answer to a request for a change, as read from its structured output.</summary>
/// <param name="Summary">What the change does, or why no change is proposed, for the administrator.</param>
/// <param name="Configuration">The proposed sections as JSON; null when the model proposes no change.</param>
public sealed record ProposalAnswer(string Summary, string? Configuration);

/// <summary>Outcome of reading an answer: the answer, or why it cannot be used.</summary>
public sealed record ProposalAnswerResult(ProposalAnswer? Answer, IReadOnlyList<string> Errors);

/// <summary>A proposal merged into the running configuration: the complete candidate JSON, or why it cannot be used.</summary>
/// <param name="Json">The complete configuration with the proposed sections, still to be parsed strictly and validated.</param>
/// <param name="Errors">Why the proposal is refused; empty when <paramref name="Json"/> is set.</param>
public sealed record ProposalMergeResult(string? Json, IReadOnlyList<string> Errors);

/// <summary>
/// How a sentence becomes a configuration change: the instructions and answer format sent to the model, and the strict
/// checks of what comes back. The model answers with a summary and only the sections it changes (routes, rules, rate
/// limits, and five settings); each present section replaces that section of the running configuration. Everything
/// else (certificates, Let's Encrypt, other settings) cannot be changed this way. The merged result is then read like
/// an imported file: unknown properties, wrong types and invalid values are rejected, secrets kept by placeholder are
/// filled from the running configuration, and the whole configuration is validated before anyone can approve it.
/// </summary>
public static class ConfigurationProposal
{
    /// <summary>Longest request accepted from the administrator, in characters.</summary>
    public const int MaxPromptLength = 2000;

    /// <summary>Longest summary kept from the model, in characters.</summary>
    public const int MaxSummaryLength = 2000;

    private static readonly string[] Lists =
        [nameof(GatewayConfiguration.Targets), nameof(GatewayConfiguration.Routes), nameof(GatewayConfiguration.Rules), nameof(GatewayConfiguration.RateLimits)];

    private static readonly JsonDocumentOptions StrictJson = new() { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, AllowDuplicateProperties = false };

    /// <summary>The settings a proposal may change.</summary>
    public static IReadOnlyList<string> ChangeableSettings => ConfigurationSummary.AllowedSettings;

    /// <summary>The answer format (structured output): a summary and the proposed sections as a JSON string.</summary>
    public const string ResponseSchema = """
        {
          "type": "object",
          "additionalProperties": false,
          "required": ["summary", "configuration"],
          "properties": {
            "summary": {
              "type": "string",
              "description": "One to three plain sentences for the administrator: what the proposed change does, or why no change is proposed."
            },
            "configuration": {
              "type": "string",
              "description": "A JSON object with only the sections that change (Targets, Routes, Rules, RateLimits, Settings), serialized as a string; an empty string when no change is proposed."
            }
          }
        }
        """;

    /// <summary>The system prompt: what the gateway is, the rules of a proposal and the configuration's JSON schema.</summary>
    public static string Instructions { get; } = $$"""
        You help the administrator of WAF Gateway, a reverse proxy with a web application firewall, change its configuration.
        You receive a sanitized summary of the current configuration and the administrator's request. Propose the change
        that does what was asked, and nothing else. The administrator reviews every proposal as a list of differences
        before it is applied; nothing is applied automatically.

        Answer in the required format:
        - "summary": one to three plain sentences about what the change does. Mention anything the administrator should
          check, such as a rule that could block legitimate traffic.
        - "configuration": a JSON object, serialized as a string, with only the sections you change. Use an empty string
          when you propose no change (the request is unclear, cannot be done with this configuration, or is not about the
          gateway's configuration), and explain why in "summary".

        Rules for "configuration":
        - Allowed top-level properties: "Targets", "Routes", "Rules", "RateLimits" and "Settings". Leave out sections you do not change.
        - "Targets", "Routes", "Rules" and "RateLimits" are each the complete new list for that section: copy the items you do not
          change exactly as they are, in the same order, and keep the names of existing items. Give new items short,
          lowercase names with hyphens.
        - "Settings" may only contain {{string.Join(", ", ConfigurationSummary.AllowedSettings.Select(s => $"\"{s}\""))}}; each one
          present is the complete new value of that setting.
        - Never include "Certificates", "SchemaVersion" or other settings: they cannot be changed this way.
        - Values shown as "{{ConfigurationSecrets.Placeholder}}" are secrets the gateway keeps. Copy them unchanged, in the
          same rule or rate limit, at the same condition position and with the same header name; the gateway fills in the
          real values. Never use this placeholder for a new value.
        - Follow the JSON schema below exactly: property names as written, enumeration values as strings, no comments and
          no properties that are not in the schema.
        - Do not weaken protection beyond what was asked. Prefer the narrowest rule that does the job (a path, host or
          method condition rather than a rule for everything).

        The JSON schema of the complete configuration:
        <schema>
        {{GatewayConfigurationJson.GetSchema().ToJsonString()}}
        </schema>
        """;

    /// <summary>The request for <paramref name="prompt"/> about <paramref name="running"/>: instructions, prompt, summary and answer format.</summary>
    public static AiRequest Request(string prompt, GatewayConfiguration running) =>
        new(Instructions, prompt, ConfigurationSummary.Create(running), ResponseSchema);

    /// <summary>Why <paramref name="prompt"/> cannot be sent; empty when it can.</summary>
    public static IReadOnlyList<string> CheckPrompt(string? prompt) =>
        string.IsNullOrWhiteSpace(prompt) ? ["Describe the change you want."]
        : prompt.Length > MaxPromptLength ? [$"The request is longer than {MaxPromptLength} characters. Describe one change at a time."]
        : [];

    /// <summary>Reads the model's structured answer strictly: exactly a summary and a configuration string.</summary>
    public static ProposalAnswerResult ReadAnswer(string? text)
    {
        const string NotExpected = "The assistant's answer is not in the expected format. Ask again.";
        if (string.IsNullOrWhiteSpace(text))
        {
            return new ProposalAnswerResult(null, ["The assistant gave an empty answer. Ask again."]);
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(text, documentOptions: StrictJson);
        }
        catch (JsonException)
        {
            return new ProposalAnswerResult(null, [NotExpected]);
        }

        if (node is not JsonObject answer
            || answer.Count != 2
            || answer["summary"] is not JsonValue summaryValue || !summaryValue.TryGetValue<string>(out var summary)
            || answer["configuration"] is not JsonValue configurationValue || !configurationValue.TryGetValue<string>(out var configuration))
        {
            return new ProposalAnswerResult(null, [NotExpected]);
        }

        summary = summary.Trim();
        if (summary.Length > MaxSummaryLength)
        {
            summary = summary[..MaxSummaryLength] + "…";
        }

        return new ProposalAnswerResult(new ProposalAnswer(summary, string.IsNullOrWhiteSpace(configuration) ? null : configuration.Trim()), []);
    }

    /// <summary>
    /// Puts the proposed sections into a copy of <paramref name="running"/>. Refuses anything but the allowed sections
    /// and settings; the result still has to be parsed strictly and validated (it is not trusted yet).
    /// </summary>
    public static ProposalMergeResult Merge(string? proposal, GatewayConfiguration running)
    {
        ArgumentNullException.ThrowIfNull(running);
        if (string.IsNullOrWhiteSpace(proposal))
        {
            return Refused("The proposal contains no changes.");
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(proposal, documentOptions: StrictJson);
        }
        catch (JsonException ex)
        {
            return Refused($"The proposal is not valid JSON: {ex.Message}");
        }

        if (node is not JsonObject sections)
        {
            return Refused("The proposal is not a JSON object.");
        }

        if (sections.Count == 0)
        {
            return Refused("The proposal contains no changes.");
        }

        var errors = new List<string>();
        var merged = JsonNode.Parse(GatewayConfigurationJson.Serialize(running))!.AsObject();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in sections)
        {
            if (!seen.Add(name))
            {
                errors.Add($"The proposal contains '{name}' more than once.");
                continue;
            }

            if (Lists.FirstOrDefault(l => string.Equals(l, name, StringComparison.OrdinalIgnoreCase)) is { } list)
            {
                if (value is JsonArray items)
                {
                    merged[list] = items.DeepClone();
                }
                else
                {
                    errors.Add($"'{list}' in the proposal must be a list.");
                }
            }
            else if (string.Equals(name, nameof(GatewayConfiguration.Settings), StringComparison.OrdinalIgnoreCase))
            {
                MergeSettings(value, merged, errors);
            }
            else
            {
                errors.Add($"The proposal changes '{name}', which the assistant may not change. It may only change targets, routes, rules, rate limits and the settings {string.Join(", ", ChangeableSettings)}.");
            }
        }

        return errors.Count > 0 ? new ProposalMergeResult(null, errors) : new ProposalMergeResult(merged.ToJsonString(), []);
    }

    private static void MergeSettings(JsonNode? value, JsonObject merged, List<string> errors)
    {
        if (value is not JsonObject proposed)
        {
            errors.Add("'Settings' in the proposal must be an object.");
            return;
        }

        var settings = merged[nameof(GatewayConfiguration.Settings)] as JsonObject ?? [];
        merged[nameof(GatewayConfiguration.Settings)] = settings;
        foreach (var (name, setting) in proposed)
        {
            if (ConfigurationSummary.AllowedSettings.FirstOrDefault(s => string.Equals(s, name, StringComparison.OrdinalIgnoreCase)) is { } allowed)
            {
                settings[allowed] = setting?.DeepClone();
            }
            else
            {
                errors.Add($"The proposal changes the setting '{name}', which the assistant may not change. It may only change the settings {string.Join(", ", ChangeableSettings)}.");
            }
        }
    }

    private static ProposalMergeResult Refused(string error) => new(null, [error]);
}
