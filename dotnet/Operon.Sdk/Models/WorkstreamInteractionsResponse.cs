using System;
using System.Linq;

namespace Operon.Sdk.Models;

/// <summary>
/// Workstream interactions response payload.
/// </summary>
public sealed class WorkstreamInteractionsResponse
{
    public WorkstreamInteraction[] Interactions { get; set; } = Array.Empty<WorkstreamInteraction>();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public bool HasMore { get; set; }

    internal void NormalizeAliases()
    {
        foreach (var item in Interactions.Where(item => item is not null))
        {
            item.NormalizeAliases();
        }
    }
}
