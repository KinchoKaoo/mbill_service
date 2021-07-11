using Autofac;
using mbill_service.Core.AOP.Middleware;
using mbill_service.Core.Common.Configs;
using mbill_service.Core.Extensions.ServiceCollection;
using mbill_service.Modules;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using System.Reflection;

namespace mbill_service
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddController();//����ע��Controller
            services.AddJwtBearer();//����Jwt
            services.AddSwagger();//����ע��Swagger
            services.AddCap();//����CAP
            services.AddAutoMapper();//����ʵ��ӳ��
            services.AddCsRedisCore();//����ע��Redis����
            services.AddMiniProfilerSetup();//����ע����
            services.AddIpRateLimiting();//����ע������
            services.AddHealthChecks();//����ע�ὡ�����
            services.AddCorsConfig();//���ÿ���

        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            builder.RegisterModule(new AutofacModule());//ע��һЩ����
            builder.RegisterModule(new RepositoryModule());//ע��ִ�
            builder.RegisterModule(new ServiceModule());//ע�����
            builder.RegisterModule(new DependencyModule());//�Զ�ע�ᣬ����Abp�еļ̳ж�Ӧ�Ľӿھͻ�ע���Ӧ�ӿڵ���������
            builder.RegisterModule(new FreeSqlModule());//ע��FreeSql
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger().UseSwaggerUI(() => GetType().GetTypeInfo().Assembly.GetManifestResourceStream("mbill_service.index.html"));
            }
            //����
            app.UseCors(Appsettings.Cors.CorsName);

            //��̬�ļ�
            app.UseStaticFiles();

            // Ip����
            app.UseIpLimitMilddleware();

            // ��¼ip����
            app.UseMiddleware<IPLogMilddleware>();

            ////�쳣�����м��
            //app.UseMiddleware<ExceptionHandlerMiddleware>();

            //��֤�м��
            app.UseAuthentication();

            // ���ܷ���
            app.UseMiniProfiler();

            app.UseRouting()
                .UseAuthorization()
                .UseEndpoints(endpoints =>
                {
                    endpoints.MapControllers();
                    endpoints.MapHealthChecks("/health");
                });
        }
    }
}
