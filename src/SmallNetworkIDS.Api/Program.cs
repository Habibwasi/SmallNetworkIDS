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
builder.Services.AddSingleton<MlInferenceEngine>();
builder.Services.AddSingleton<AlertManager>();
builder.Services.AddSingleton<DataExporter>();
builder.Services.AddSingleton<IDSService>();

var app = builder.Build();

app.UseCors("AllowReactApp");
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
