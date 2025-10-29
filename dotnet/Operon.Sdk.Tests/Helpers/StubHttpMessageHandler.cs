using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http.Json;

namespace Operon.Sdk.Tests.Helpers;

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();

    public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        => _responses.Enqueue(responseFactory);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!_responses.TryDequeue(out var factory))
        {
            throw new InvalidOperationException($"No response queued for {request.Method} {request.RequestUri}");
        }

        return Task.FromResult(factory(request));
    }

    public static HttpResponseMessage Json(HttpStatusCode statusCode, object payload)
    {
        var message = new HttpResponseMessage(statusCode)
        {
            Content = JsonContent.Create(payload)
        };
        return message;
    }
}
