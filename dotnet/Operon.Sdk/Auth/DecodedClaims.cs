using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Operon.Sdk.Internal;

namespace Operon.Sdk.Auth;

/// <summary>
/// Parsed JWT claims used by SDK components.
/// </summary>
public sealed class DecodedClaims
{
    public string? ParticipantDid { get; init; }
    public string? WorkstreamId { get; init; }
    public string? CustomerId { get; init; }
    public string? WorkspaceId { get; init; }
    public string? Email { get; init; }
    public string? Name { get; init; }
    public IReadOnlyList<string> TenantIds { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
    public string? MemberId { get; init; }
    public string? SessionId { get; init; }
    public string? OrgId { get; init; }
    public string? ParticipantId { get; init; }
    public string? ClientId { get; init; }
    public string? AuthorizedParty { get; init; }
    public long ExpiresAtUnix { get; init; }

    public static DecodedClaims Decode(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new DecodedClaims();
        }

        var segments = token.Split('.');
        if (segments.Length < 2)
        {
            return new DecodedClaims();
        }

        try
        {
            var payloadBytes = SdkModelHelpers.DecodeBase64Url(segments[1]);
            using var document = JsonDocument.Parse(payloadBytes);
            var root = document.RootElement;

            var workstream = ReadString(root, "workstream_id");
            if (string.IsNullOrWhiteSpace(workstream))
            {
                workstream = ReadString(root, "channel_id");
            }

            return new DecodedClaims
            {
                ParticipantDid = ReadString(root, "participant_did"),
                WorkstreamId = workstream,
                CustomerId = ReadString(root, "customer_id"),
                WorkspaceId = ReadString(root, "workspace_id"),
                Email = ReadString(root, "email"),
                Name = ReadString(root, "name"),
                TenantIds = ReadStringArray(root, "tenant_ids"),
                Roles = ReadStringArray(root, "roles"),
                MemberId = ReadString(root, "member_id"),
                SessionId = ReadString(root, "session_id"),
                OrgId = ReadString(root, "org_id"),
                ParticipantId = ReadString(root, "participant_id"),
                ClientId = ReadString(root, "client_id"),
                AuthorizedParty = ReadString(root, "azp"),
                ExpiresAtUnix = ReadLong(root, "exp")
            };
        }
        catch
        {
            return new DecodedClaims();
        }
    }

    private static string? ReadString(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
        {
            var text = value.GetString();
            return string.IsNullOrWhiteSpace(text) ? null : text.Trim();
        }

        return null;
    }

    private static long ReadLong(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.Number)
        {
            return value.GetInt64();
        }

        return 0;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var list = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var text = item.GetString();
            if (!string.IsNullOrWhiteSpace(text))
            {
                list.Add(text.Trim());
            }
        }

        return list.ToArray();
    }
}
