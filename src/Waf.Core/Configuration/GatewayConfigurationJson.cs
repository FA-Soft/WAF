using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Text.RegularExpressions;

namespace Waf.Core.Configuration;

/// <summary>Outcome of parsing a configuration document.</summary>
/// <param name="Configuration">The parsed configuration, or null when the JSON itself could not be read.</param>
/// <param name="Errors">JSON and validation errors; empty when the configuration is valid.</param>
public sealed record ConfigurationParseResult(GatewayConfiguration? Configuration, IReadOnlyList<string> Errors)
{
    public bool IsValid => Configuration is not null && Errors.Count == 0;
}

/// <summary>
/// Reads and writes <see cref="GatewayConfiguration"/> as JSON, and produces its JSON schema.
/// </summary>
/// <remarks>
/// Reading is strict: unknown properties (usually typos), numbers for enum values and nulls for
/// required values are errors. Comments and trailing commas are allowed; property names are
/// case-insensitive.
/// </remarks>
public static partial class GatewayConfigurationJson
{
    /// <summary>JSON Schema dialect used by <see cref="GetSchema"/>.</summary>
    public const string SchemaDialect = "https://json-schema.org/draft/2020-12/schema";

    /// <summary>Serializer options used for all configuration documents.</summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    public static string Serialize(GatewayConfiguration configuration) =>
        JsonSerializer.Serialize(configuration, Options);

    /// <summary>Parses <paramref name="json"/> and validates the result.</summary>
    public static ConfigurationParseResult Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        GatewayConfiguration? configuration;
        try
        {
            // The serializer silently skips null for get-only collections (e.g. "Routes": null), so check
            // nulls against the model first.
            var document = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
            if (FindDisallowedNull(document, Options.GetTypeInfo<GatewayConfiguration>(), "$") is { } nullPath)
            {
                return new ConfigurationParseResult(null, [$"Invalid value at {nullPath}: a value is required (null is not allowed)."]);
            }

            configuration = JsonSerializer.Deserialize<GatewayConfiguration>(json, Options);
        }
        catch (JsonException ex)
        {
            return new ConfigurationParseResult(null, [Describe(ex)]);
        }

        if (configuration is null)
        {
            return new ConfigurationParseResult(null, ["The configuration is empty (null)."]);
        }

        return new ConfigurationParseResult(configuration, GatewayConfigurationValidator.Validate(configuration));
    }

    /// <summary>JSON schema of the configuration document, generated from the model.</summary>
    public static JsonObject GetSchema()
    {
        var schema = (JsonObject)JsonSchemaExporter.GetJsonSchemaAsNode(
            Options,
            typeof(GatewayConfiguration),
            new JsonSchemaExporterOptions
            {
                TreatNullObliviousAsNonNullable = true,
                TransformSchemaNode = RemoveNullFromNonNullableProperties,
            });

        var result = new JsonObject
        {
            ["$schema"] = SchemaDialect,
            ["title"] = $"{ProductInfo.Name} configuration",
        };

        foreach (var (key, value) in schema)
        {
            result[key] = value?.DeepClone();
        }

        return result;
    }

    /// <summary>Returns the JSON path of the first null that the model does not allow, or null if there is none.</summary>
    private static string? FindDisallowedNull(JsonNode? node, JsonTypeInfo typeInfo, string path)
    {
        switch (node)
        {
            case JsonObject obj when typeInfo.Kind == JsonTypeInfoKind.Object:
                foreach (var (name, value) in obj)
                {
                    var property = typeInfo.Properties.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
                    if (property is null)
                    {
                        continue; // unknown properties are reported by the serializer
                    }

                    var childPath = $"{path}.{property.Name}";
                    if (value is null)
                    {
                        if (!property.IsGetNullable)
                        {
                            return childPath;
                        }

                        continue;
                    }

                    if (FindDisallowedNull(value, Options.GetTypeInfo(property.PropertyType), childPath) is { } found)
                    {
                        return found;
                    }
                }

                break;

            case JsonArray array when typeInfo.Kind == JsonTypeInfoKind.Enumerable && typeInfo.ElementType is { } elementType:
                // No list in the model allows null entries.
                var elementInfo = Options.GetTypeInfo(elementType);
                for (var i = 0; i < array.Count; i++)
                {
                    var elementPath = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{path}[{i}]");
                    if (array[i] is null)
                    {
                        return elementPath;
                    }

                    if (FindDisallowedNull(array[i], elementInfo, elementPath) is { } found)
                    {
                        return found;
                    }
                }

                break;
        }

        return null;
    }

    /// <summary>
    /// The exporter marks get-only collection properties (e.g. <c>Routes</c>) as nullable; they are not.
    /// </summary>
    private static JsonNode RemoveNullFromNonNullableProperties(JsonSchemaExporterContext context, JsonNode schema)
    {
        if (context.PropertyInfo is { IsGetNullable: false }
            && schema is JsonObject node
            && node["type"] is JsonArray types
            && types.Any(t => (string?)t == "null"))
        {
            var remaining = types.Select(t => (string?)t).Where(t => t != "null").ToList();
            node["type"] = remaining.Count == 1 ? remaining[0] : new JsonArray([.. remaining.Select(t => (JsonNode?)t)]);
        }

        return schema;
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            PreferredObjectCreationHandling = JsonObjectCreationHandling.Populate,
            RespectNullableAnnotations = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        };
        options.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false));
        options.MakeReadOnly();
        return options;
    }

    /// <summary>Turns a serializer exception into a plain-language message with the JSON location.</summary>
    internal static string Describe(JsonException exception)
    {
        var path = string.IsNullOrEmpty(exception.Path) || exception.Path == "$" ? "the document" : exception.Path;
        var message = exception.Message;

        var unmapped = UnmappedPattern().Match(message);
        if (unmapped.Success)
        {
            return $"Unknown setting '{unmapped.Groups["name"].Value}' in {ParentPath(exception.Path)}. Check the spelling.";
        }

        var conversion = ConversionPattern().Match(message);
        if (conversion.Success)
        {
            var typeName = conversion.Groups["type"].Value;
            var type = typeof(GatewayConfiguration).Assembly.GetType(typeName);
            var expected = type switch
            {
                { IsEnum: true } => $"one of: {string.Join(", ", Enum.GetNames(type))}",
                _ when typeName is "System.Int32" or "System.Int64" => "a whole number",
                _ when typeName == "System.Boolean" => "true or false",
                _ when typeName == "System.String" => "text in quotes",
                _ when typeName.Contains("IList", StringComparison.Ordinal) => "a list [ ... ]",
                _ => "a different kind of value",
            };
            return $"Invalid value at {path}: expected {expected}.";
        }

        if (message.Contains("doesn't allow setting null values", StringComparison.Ordinal))
        {
            return $"Invalid value at {path}: a value is required (null is not allowed).";
        }

        if (exception.LineNumber is { } line)
        {
            var position = exception.BytePositionInLine ?? 0;
            return $"Invalid JSON at line {line + 1}, position {position + 1}: {FirstSentence(message)}";
        }

        return $"Invalid value at {path}: {FirstSentence(message)}";
    }

    private static string ParentPath(string? path) =>
        string.IsNullOrEmpty(path) || path == "$" ? "the document" : path;

    private static string FirstSentence(string message)
    {
        var cut = message.IndexOf(" Path:", StringComparison.Ordinal);
        return (cut >= 0 ? message[..cut] : message).Trim();
    }

    [GeneratedRegex(@"The JSON property '(?<name>[^']*)' could not be mapped")]
    private static partial Regex UnmappedPattern();

    [GeneratedRegex(@"could not be converted to (?<type>[^\s.]+(?:\.[^\s.]+)*)\.")]
    private static partial Regex ConversionPattern();
}
