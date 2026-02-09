using System;
using System.Net.Http;

namespace Operon.Sdk;

/// <summary>
/// Configuration for PAT-scoped client API calls.
/// </summary>
public sealed class ClientApiConfig
{
    public Uri? BaseUri { get; init; }
    public HttpClient? HttpClient { get; init; }
}
