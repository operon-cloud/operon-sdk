using System;
using System.Net;
using System.Text.Json;

namespace Operon.Sdk.Errors;

/// <summary>
/// Base exception for all Operon SDK failures.
/// </summary>
public class OperonSdkException : Exception
{
    public OperonSdkException(string message)
        : base(message)
    {
    }

    public OperonSdkException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Thrown when client-side validation fails before sending a request.
/// </summary>
public sealed class ValidationException : OperonSdkException
{
    public ValidationException(string message) : base(message)
    {
    }
}

/// <summary>
/// Wraps transport-level failures (e.g., network, timeout).
/// </summary>
public sealed class TransportException : OperonSdkException
{
    public TransportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Represents an error returned by the Operon API.
/// </summary>
public sealed class OperonApiException : OperonSdkException
{
    public OperonApiException(string message, HttpStatusCode statusCode, string? code = null, JsonElement? details = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
        Details = details;
    }

    /// <summary>HTTP status code returned by Operon.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Optional machine-readable error code.</summary>
    public string? Code { get; }

    /// <summary>Optional JSON payload containing additional error context.</summary>
    public JsonElement? Details { get; }
}
