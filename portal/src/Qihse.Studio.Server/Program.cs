using Qihse.Studio.Server.Hubs;
using Qihse.Studio.Server.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddSignalR();

// Register background telemetry & mesh service
builder.Services.AddSingleton<ClusterMeshService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ClusterMeshService>());

// CORS for Vite dev server (port 5173)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowViteDev", policy =>
    {
        policy.WithOrigins("http://localhost:5173", "http://127.0.0.1:5173")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

app.UseCors("AllowViteDev");

// Static files for production built SPA
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthorization();

app.MapControllers();
app.MapHub<TelemetryHub>("/hub/telemetry");

// Fallback to SPA index.html for client-side routing
app.MapFallbackToFile("index.html");

app.Run();
