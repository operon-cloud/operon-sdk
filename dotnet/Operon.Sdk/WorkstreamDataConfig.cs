using System;
using System.Net.Http;

namespace Operon.Sdk;

/// <summary>
/// Configuration for PAT-scoped workstream data calls.
/// </summary>
public sealed class WorkstreamDataConfig
{
    public Uri? BaseUri { get; init; }
    public HttpClient? HttpClient { get; init; }
}
