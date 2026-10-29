using System.Net;

namespace ModelSafetyCheck.Hub;

/// <summary>Read-only HTTP transport. Credentials are attached only to the Hugging Face HTTPS origin.</summary>
internal static class RemoteHttp
{
    public static HttpClient Create(HttpMessageHandler? handler = null) => new(new RetryHandler
    {
        InnerHandler = handler ?? new SocketsHttpHandler { MaxResponseDrainSize = 0 },
    })
    {
        Timeout = TimeSpan.FromSeconds(60),
        DefaultRequestHeaders = { UserAgent = { new("modelcheck", "0.3.0") } },
    };

    sealed class RetryHandler : DelegatingHandler
    {
        static HttpRequestMessage Copy(HttpRequestMessage request)
        {
            var copy = new HttpRequestMessage(request.Method, request.RequestUri);
            foreach (var header in request.Headers)
                copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
            // Never put HF_TOKEN on the client's default headers: the same transport also reads other providers.
            if (copy.RequestUri is { Scheme: "https", Host: "huggingface.co", IsDefaultPort: true } &&
                copy.Headers.Authorization is null && Environment.GetEnvironmentVariable("HF_TOKEN") is { Length: > 0 } token)
                copy.Headers.Authorization = new("Bearer", token);
            return copy;
        }

        static bool Transient(HttpStatusCode status) => status is HttpStatusCode.TooManyRequests or
            HttpStatusCode.RequestTimeout or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

        static TimeSpan Delay(HttpResponseMessage response, int attempt)
        {
            var delay = response.Headers.RetryAfter?.Delta ??
                (response.Headers.RetryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : TimeSpan.FromSeconds(1 << attempt));
            return TimeSpan.FromSeconds(Math.Clamp(delay.TotalSeconds, 0, 60));
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            for (var attempt = 0; ; attempt++)
            {
                using var copy = Copy(request);
                var response = base.Send(copy, cancellationToken);
                if (attempt >= 3 || !Transient(response.StatusCode)) return response;
                var delay = Delay(response, attempt);
                response.Dispose();
                Task.Delay(delay, cancellationToken).GetAwaiter().GetResult();
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            for (var attempt = 0; ; attempt++)
            {
                using var copy = Copy(request);
                var response = await base.SendAsync(copy, cancellationToken).ConfigureAwait(false);
                if (attempt >= 3 || !Transient(response.StatusCode)) return response;
                var delay = Delay(response, attempt);
                response.Dispose();
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
