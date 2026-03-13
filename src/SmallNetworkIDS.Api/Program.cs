using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using SmallNetworkIDS.Api.Services;
using Microsoft.AspNetCore.Cors;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddOpenApi();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://localhost:3001")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Register IDS services as singletons
builder.Services.AddSingleton<FeatureExtractor>();
builder.Services.AddSingleton<MlInferenceEngine>(provider =>
{
    var engine = new MlInferenceEngine(provider.GetRequiredService<FeatureExtractor>());
    // Load ML model
    var modelPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../..", "model.onnx");
    if (File.Exists(modelPath))
    {
        try
        {
            engine.LoadModel(modelPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Failed to load model from {modelPath}: {ex.Message}");
        }
    }
    return engine;
});
builder.Services.AddSingleton<AlertManager>();
builder.Services.AddSingleton<DataExporter>();
builder.Services.AddSingleton<IDSService>();

// Register background service for packet capture
builder.Services.AddHostedService<IDSBackgroundService>();

var app = builder.Build();

app.UseCors("AllowReactApp");
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
