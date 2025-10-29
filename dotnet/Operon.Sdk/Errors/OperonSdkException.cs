using System;
using System.Net;
using System.Text.Json;

namespace Operon.Sdk.Errors;

/// <summary>
/// Base exception for all Operon SDK failures.
/// </summary>
public class OperonSdkException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OperonSdkException"/> class with a message.
    /// </summary>
    /// <param name="message">Human-readable message describing the failure.</param>
    public OperonSdkException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OperonSdkException"/> class with a message and inner exception.
    /// </summary>
    /// <param name="message">Human-readable message describing the failure.</param>
    /// <param name="innerException">Underlying exception that caused the error.</param>
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
    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationException"/> class.
    /// </summary>
    /// <param name="message">Human-readable message describing the validation error.</param>
    public ValidationException(string message) : base(message)
    {
    }
}

/// <summary>
/// Wraps transport-level failures (e.g., network, timeout).
/// </summary>
public sealed class TransportException : OperonSdkException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TransportException"/> class.
    /// </summary>
    /// <param name="message">Human-readable message describing the failure.</param>
    /// <param name="innerException">Underlying network/transport exception.</param>
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
    /// <summary>
    /// Initializes a new instance of the <see cref="OperonApiException"/> class.
    /// </summary>
    /// <param name="message">Human-readable message describing the API failure.</param>
    /// <param name="statusCode">HTTP status code returned by Operon.</param>
    /// <param name="code">Optional machine readable error code.</param>
    /// <param name="details">Optional JSON payload providing additional error context.</param>
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
