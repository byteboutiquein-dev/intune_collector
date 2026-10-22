// SPDX-License-Identifier: Apache-2.0

using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace IntuneReliability.Collector;

public sealed class CollectorApiClient(HttpClient httpClient, IOptions<CollectorOptions> options)
{
    private readonly Uri baseUri = new(options.Value.ApiBaseUrl.TrimEnd('/') + "/");

    public async Task<string> ClaimAsync(string token, CancellationToken cancellationToken)
    {
        using var response = await httpClient.PostAsJsonAsync(new Uri(baseUri, "api/diagnostics/collector/claim"), new ClaimRequest(token), cancellationToken);
        response.EnsureSuccessStatusCode();
        var claimed = await response.Content.ReadFromJsonAsync<ClaimResponse>(cancellationToken: cancellationToken);
        return claimed?.Credential ?? throw new InvalidOperationException("Collector claim returned no credential.");
    }

    public async Task UploadAsync(string credential, CollectorBatch batch, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "api/diagnostics/collector/events"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        request.Content = JsonContent.Create(batch);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
