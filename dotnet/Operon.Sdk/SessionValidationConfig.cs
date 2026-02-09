using System;
using System.Net.Http;

namespace Operon.Sdk;

/// <summary>
/// Configuration for PAT session validation calls.
/// </summary>
public sealed class SessionValidationConfig
{
    public Uri? BaseUri { get; init; }
    public HttpClient? HttpClient { get; init; }
}
