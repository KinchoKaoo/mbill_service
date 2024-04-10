using MongoDB.Driver;
using Serilog.Events;

namespace Mbill;

public class Program
{
    public static async Task Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console(LogEventLevel.Verbose, "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} <s:{SourceContext}>{NewLine}{Exception}")
            .WriteTo.MongoDBBson(cfg =>
            {
                var mongoDbInstance = new MongoClient(Appsettings.MongoDBCon).GetDatabase(Appsettings.MongoDBName);
                Console.WriteLine(Appsettings.MongoDBCon);
                cfg.SetMongoDatabase(mongoDbInstance);
                cfg.SetCollectionName("logs");      
            }, LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .CreateLogger();
        try
        {
            // ����ѩ��ID������
            SnowFlake.SnowFlakeConfig();

            IHost webHost = CreateHostBuilder(args).Build();
            try
            {
                using var scope = webHost.Services.CreateScope();
                // get the IpPolicyStore instance
                var ipPolicyStore = scope.ServiceProvider.GetRequiredService<IIpPolicyStore>();
                // seed IP data from appsettings
                await ipPolicyStore.SeedAsync(); 
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "IIpPolicyStore RUN Error");
            }
            await webHost.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Host terminated unexpectedly");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .UseServiceProviderFactory(new AutofacServiceProviderFactory())//���Autofac���񹤳�
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
#if DEBUG
#endif
            }).UseSerilog();//����Serilog;
}
