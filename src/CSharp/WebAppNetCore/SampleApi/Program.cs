using SampleApi;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSampleApi();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapSampleApiEndpoints();
app.Run();

/// <summary>
/// The entry point. The test project uses it with WebApplicationFactory.
/// </summary>
public partial class Program
{
}
