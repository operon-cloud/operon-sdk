using System;
using System.Linq;

namespace Operon.Sdk.Models;

/// <summary>
/// Workstream participants response payload.
/// </summary>
public sealed class WorkstreamParticipantsResponse
{
    public WorkstreamParticipant[] Participants { get; set; } = Array.Empty<WorkstreamParticipant>();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public bool HasMore { get; set; }

    internal void NormalizeAliases()
    {
        foreach (var item in Participants.Where(item => item is not null))
        {
            item.NormalizeAliases();
        }
    }
}
