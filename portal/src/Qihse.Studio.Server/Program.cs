using Qihse.Studio.Server.Hubs;
using Qihse.Studio.Server.Middleware;
using Qihse.Studio.Server.Services;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? "http://0.0.0.0:5100");

builder.Services.AddControllers();
builder.Services.AddSignalR();
builder.Services.AddSingleton<ClusterMeshService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ClusterMeshService>());
builder.Services.AddCors(options => options.AddPolicy("AllowViteDev", policy =>
    policy.WithOrigins("http://localhost:5173", "http://127.0.0.1:5173")
          .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

var app = builder.Build();
// Neither private source addresses nor CORS are authentication.
app.UseMiddleware<LanOnlyMiddleware>();
app.UseMiddleware<StudioAuthMiddleware>();
app.UseCors("AllowViteDev");
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapControllers();
app.MapHub<TelemetryHub>("/hub/telemetry");
app.MapFallbackToFile("index.html");
app.Run();
