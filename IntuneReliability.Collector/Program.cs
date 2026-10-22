// SPDX-License-Identifier: Apache-2.0

using IntuneReliability.Collector;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Intune Reliability Evidence Collector");
builder.Services.AddOptions<CollectorOptions>()
    .Bind(builder.Configuration.GetSection("Collector"))
    .Validate(options => Uri.TryCreate(options.ApiBaseUrl, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.IsLoopback), "Collector ApiBaseUrl must be HTTPS.")
    .Validate(options => options.PollSeconds is >= 15 and <= 3600, "Collector PollSeconds must be between 15 and 3600.")
    .Validate(options => options.MaximumEventsPerBatch is >= 1 and <= 500, "Collector MaximumEventsPerBatch must be between 1 and 500.")
    .ValidateOnStart();
builder.Services.AddHttpClient<CollectorApiClient>();
builder.Services.AddSingleton<CredentialStore>();
builder.Services.AddSingleton<CursorStore>();
builder.Services.AddSingleton<ImeEventNormalizer>();
builder.Services.AddHostedService<CollectorWorker>();
await builder.Build().RunAsync();
