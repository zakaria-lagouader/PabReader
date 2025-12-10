using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Azure.SignalR.Management;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.IO.Ports;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace PabReader
{
    // --- Configuration Models ---
    public class SerialSettings
    {
        public string PortName { get; set; } = "COM1";
        public int BaudRate { get; set; } = 9600;
        public bool Simulate { get; set; }
        public string PontId { get; set; } = "PaB-01";
    }

    public class RemoteApiSettings
    {
        public string RegisterUrl { get; set; } = "";
        public string ApiKey { get; set; } = "";
    }

    public class AzureSignalRSettings
    {
        public string ConnectionString1 { get; set; } = "";
        public string ConnectionString2 { get; set; } = "";
        public string HubName { get; set; } = "";
    }

    public class Program
    {
        public static async Task Main(string[] args)
        {
            // 1. Set the Base Directory so the .exe finds appsettings.json
            var baseDir = AppContext.BaseDirectory;
            Directory.SetCurrentDirectory(baseDir);

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = args,
                ContentRootPath = baseDir, // CRITICAL for .exe
                ApplicationName = System.Diagnostics.Process.GetCurrentProcess().ProcessName
            });

            // 2. Configure Kestrel for HTTPS using a file (Required for standalone PCs)
            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.ListenAnyIP(5858, listenOptions =>
                {
                    // Look for certificate.pfx next to the exe
                    var certPath = Path.Combine(baseDir, "certificate.pfx");
                    if (File.Exists(certPath))
                    {
                        // Password for the cert (set this when creating the cert)
                        listenOptions.UseHttps(certPath, "1234");
                    }
                    else
                    {
                        // Fallback to HTTP if cert is missing (logs a warning)
                        Console.WriteLine("⚠️ WARNING: certificate.pfx not found. HTTPS will not work.");
                    }
                });
            });

            builder.Services.AddWindowsService();

            builder.Services.Configure<SerialSettings>(builder.Configuration.GetSection("SerialSettings"));
            builder.Services.Configure<RemoteApiSettings>(builder.Configuration.GetSection("RemoteApiSettings"));
            builder.Services.Configure<AzureSignalRSettings>(builder.Configuration.GetSection("AzureSignalR"));

            builder.Services.AddHttpClient("InsecureClient", client =>
            {
                client.Timeout = TimeSpan.FromSeconds(10);
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                return new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
                };
            });

            builder.Services.AddSingleton<DeviceIdentityService>();
            builder.Services.AddSingleton<SignalRService>();
            builder.Services.AddHostedService<SerialWorker>();
            builder.Services.AddCors();

            var app = builder.Build();

            app.UseCors(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            app.MapGet("/device-proof", (DeviceIdentityService deviceService, IOptions<SerialSettings> settings) =>
            {
                return Results.Json(deviceService.GenerateProof());
            });

            // Auto-register on startup
            _ = Task.Run(async () =>
            {
                using var scope = app.Services.CreateScope();
                var deviceService = scope.ServiceProvider.GetRequiredService<DeviceIdentityService>();
                await deviceService.RegisterWithApiAsync();
            });

            await app.RunAsync();
        }
    }

    // ---------------------------------------------------------
    // DeviceIdentityService
    public class DeviceIdentityService
    {
        private readonly ILogger<DeviceIdentityService> _logger;
        private readonly IHttpClientFactory _httpFactory;
        private readonly RemoteApiSettings _apiSettings;
        private string _deviceId = "";
        private byte[] _deviceSecret = Array.Empty<byte>();
        private const string DeviceIdFile = "device-id.txt";
        private const string DeviceSecretFile = "device-secret.txt";
        private string _channel = "";
        public string DeviceId => _deviceId;
        public string Channel => _channel;

        public DeviceIdentityService(ILogger<DeviceIdentityService> logger, IHttpClientFactory httpFactory, IOptions<RemoteApiSettings> options)
        {
            _logger = logger;
            _httpFactory = httpFactory;
            _apiSettings = options.Value;
            LoadOrCreateIdentity();
        }

        private void LoadOrCreateIdentity()
        {
            var baseDir = AppContext.BaseDirectory;
            var idPath = Path.Combine(baseDir, DeviceIdFile);
            var secPath = Path.Combine(baseDir, DeviceSecretFile);

            if (File.Exists(idPath) && File.Exists(secPath))
            {
                _deviceId = File.ReadAllText(idPath).Trim();
                _deviceSecret = Convert.FromHexString(File.ReadAllText(secPath).Trim());
            }
            else
            {
                _deviceId = Guid.NewGuid().ToString("N");
                _deviceSecret = RandomNumberGenerator.GetBytes(32);
                File.WriteAllText(idPath, _deviceId);
                File.WriteAllText(secPath, Convert.ToHexString(_deviceSecret));
            }
            _channel = Guid.NewGuid().ToString("N");
        }

        public async Task RegisterWithApiAsync()
        {
            try
            {
                var client = _httpFactory.CreateClient("InsecureClient");
                var payload = new { DeviceId = _deviceId, SecretHex = Convert.ToHexString(_deviceSecret) };
                var request = new HttpRequestMessage(HttpMethod.Post, _apiSettings.RegisterUrl);
                request.Headers.Add("X-Api-Key", _apiSettings.ApiKey);
                request.Content = JsonContent.Create(payload);
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                _logger.LogInformation("Device registered.");
            }
            catch (Exception ex)
            {
                _logger.LogError("Registration failed: " + ex.Message);
            }
        }

        public object GenerateProof()
        {
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce = Guid.NewGuid().ToString("N");
            var msg = $"{_deviceId}.{ts}.{nonce}";
            using var hmac = new HMACSHA256(_deviceSecret);
            var sigBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
            return new { deviceId = _deviceId, ts, nonce, sig = Convert.ToHexString(sigBytes), channel = _channel };
        }
    }

    // ---------------------------------------------------------
    // SignalRService
    public class SignalRService : IAsyncDisposable
    {
        private readonly ILogger<SignalRService> _logger;
        private readonly AzureSignalRSettings _settings;
        private ServiceHubContext? _hub1;

        public SignalRService(ILogger<SignalRService> logger, IOptions<AzureSignalRSettings> options)
        {
            _logger = logger;
            _settings = options.Value;
        }

        public async Task InitializeAsync()
        {
            _hub1 = await CreateHubAsync(_settings.ConnectionString1);
        }

        private async Task<ServiceHubContext> CreateHubAsync(string conn)
        {
            var mgr = new ServiceManagerBuilder()
                .WithOptions(o => o.ConnectionString = conn)
                .BuildServiceManager();

            return await mgr.CreateHubContextAsync(_settings.HubName, default);
        }

        public async Task BroadcastWeightAsync(string devId, string channel, string pontId, decimal w)
        {
            var g = $"device:{devId}";
            var s = w.ToString("F2", CultureInfo.InvariantCulture);

            await Task.WhenAll(
                SendSafe(_hub1, g, channel, pontId, s)
            );
        }

        private async Task SendSafe(ServiceHubContext? h, string g, string c, string p, string v)
        {
            if (h != null)
            {
                try
                {
                    await h.Clients.Group(g).SendAsync(c, p, v);
                }
                catch
                {
                    // swallow errors for robustness
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_hub1 != null) await _hub1.DisposeAsync();
        }
    }

    // ---------------------------------------------------------
    // SerialWorker
    public class SerialWorker : BackgroundService
    {
        private readonly ILogger<SerialWorker> _logger;
        private readonly SerialSettings _settings;
        private readonly SignalRService _signalR;
        private readonly DeviceIdentityService _identity;
        private SerialPort? _serialPort;
        private readonly StringBuilder _buffer = new();
        private bool _lastSentWasZero = false;

        public SerialWorker(
            ILogger<SerialWorker> log,
            IOptions<SerialSettings> opt,
            SignalRService sig,
            DeviceIdentityService id)
        {
            _logger = log;
            _settings = opt.Value;
            _signalR = sig;
            _identity = id;
        }

        public override async Task StartAsync(CancellationToken ct)
        {
            await _signalR.InitializeAsync();
            if (!_settings.Simulate)
                Open();
            await base.StartAsync(ct);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                if (_settings.Simulate)
                {
                    decimal w = new Random().Next(1000, 1200);
                    await Process(w, "SIM");
                    await Task.Delay(1000, ct);
                }
                else
                {
                    await Task.Delay(1000, ct);
                }
            }
        }

        private void Open()
        {
            try
            {
                _serialPort = new SerialPort(_settings.PortName, _settings.BaudRate, Parity.None, 8, StopBits.One)
                {
                    Handshake = Handshake.None,
                    DtrEnable = true,
                    RtsEnable = true,
                    Encoding = Encoding.ASCII,
                    ReadTimeout = 1000,
                    WriteTimeout = 500,
                    NewLine = "\r"
                };
                _serialPort.DataReceived += OnData;
                _serialPort.Open();
                _logger.LogInformation("Serial Open");
            }
            catch
            {
                _logger.LogError("Serial Fail");
            }
        }

        private void OnData(object? s, SerialDataReceivedEventArgs e)
        {
            try
            {
                _buffer.Append(_serialPort!.ReadExisting());
                ProcessBuffer();
            }
            catch
            {
            }
        }

        private void ProcessBuffer()
        {
            string c = _buffer.ToString();
            while (c.Contains("\r"))
            {
                int i = c.IndexOf("\r", StringComparison.Ordinal);
                string f = c.Substring(0, i).Trim();
                _buffer.Remove(0, i + 1);
                c = _buffer.ToString();

                var m = Regex.Match(f, @"[-+]?\d+(?:[.,]\d+)?");
                if (m.Success &&
                    decimal.TryParse(
                        m.Value.Replace(",", "."),
                        NumberStyles.Any,
                        CultureInfo.InvariantCulture,
                        out decimal w))
                {
                    _ = Process(w, f);
                }
            }
        }

        private async Task Process(decimal w, string r)
        {
            bool z = w == 0;
            if (z && _lastSentWasZero) return;
            _lastSentWasZero = z;

            // Log Weights  
            _logger.LogInformation("[WEIGHT LOG] PontId={Pont} Weight={Weight}", _settings.PontId, w);
            await _signalR.BroadcastWeightAsync(_identity.DeviceId, _identity.Channel, _settings.PontId, w);
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            if (_serialPort != null && _serialPort.IsOpen)
                _serialPort.Close();

            await base.StopAsync(ct);
        }
    }
}
