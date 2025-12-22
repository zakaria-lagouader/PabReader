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
using System.Linq;

namespace PabReader
{
    // --- Configuration Models ---
    public class SerialSettings
    {
        public string PortName { get; set; } = "COM1";
        public int BaudRate { get; set; } = 9600;
        public bool Simulate { get; set; }
        public string PontId { get; set; } = "PaB-01";
        public int SendIntervalMs { get; set; } = 500;
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
            var machineName = Environment.MachineName;

            await Task.WhenAll(
                SendSafe(_hub1, g, channel, pontId, s, machineName)
            );
        }

        private async Task SendSafe(ServiceHubContext? h, string g, string c, string p, string v, string machineName)
        {
            if (h != null)
            {
                try
                {
                    await h.Clients.Group(g).SendAsync(c, p, v, machineName);
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
        private long _lastSentMs = 0;

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
            while (true)
            {
                string buf = _buffer.ToString();

                // Look for STX (0x02) and ETX (0x03) or CR (\r) as terminators
                int stx = buf.IndexOf('\x02'); // STX
                int etx = (stx >= 0) ? buf.IndexOf('\x03', stx + 1) : -1; // ETX after STX
                int term = (etx > stx) ? etx : buf.IndexOf('\r', Math.Max(0, stx + 1));

                // No complete message yet
                if (stx < 0 && term < 0)
                    return;

                int start = (stx >= 0) ? stx + 1 : 0;
                int end = term;

                if (end <= start)
                    return;

                string payload = buf.Substring(start, end - start).Trim();

                // Remove up through the terminator (ETX or CR)
                _buffer.Remove(0, end + 1);

                ProcessPayload(payload);
            }
        }

        private void ProcessPayload(string payload)
        {
            if (!TryParseWeightKg(payload, out var weight))
            {
                _logger.LogDebug("Skip (no weight parsed) | raw: {raw}", payload);
                return;
            }

            // Re-use your existing processing pipeline
            _ = Process(weight, payload);
        }

        private static bool TryParseWeightKg(string text, out decimal weight)
        {
            // Find all numeric tokens
            var matches = Regex.Matches(text, @"[-+]?\d+(?:[.,]\d+)?");
            if (matches.Count == 0)
            {
                weight = 0;
                return false;
            }

            var tokens = matches.Select(m => m.Value).ToList();

            int Digits(string s) =>
                s.Replace(".", "")
                 .Replace(",", "")
                 .TrimStart('+', '-')
                 .Count(char.IsDigit);

            // Special case: formats like "XX 1234.5 YY" (status / weight / unit)
            if (tokens.Count == 3 && Digits(tokens[0]) <= 2 && Digits(tokens[2]) <= 2)
            {
                var mid = tokens[1].Replace(',', '.');
                if (decimal.TryParse(
                        mid,
                        NumberStyles.Number,
                        CultureInfo.InvariantCulture,
                        out weight))
                {
                    return true;
                }
            }

            // General case: choose the "best" candidate
            decimal bestVal = 0;
            int bestDigits = -1;
            bool haveBest = false;

            foreach (var raw in tokens)
            {
                var norm = raw.Replace(',', '.');

                if (!decimal.TryParse(
                        norm,
                        NumberStyles.Number,
                        CultureInfo.InvariantCulture,
                        out var val))
                {
                    continue;
                }

                int d = Digits(raw);

                if (!haveBest || d > bestDigits || (d == bestDigits && Math.Abs(val) > Math.Abs(bestVal)))
                {
                    bestVal = val;
                    bestDigits = d;
                    haveBest = true;
                }
            }

            weight = haveBest ? bestVal : 0;
            return haveBest;
        }


        private async Task Process(decimal w, string raw)
        {
            // bool z = w == 0;
            // if (z && _lastSentWasZero) return;
            // _lastSentWasZero = z;

            // ---- NEW: throttle sending ----
            long now = Environment.TickCount64;
            int interval = Math.Max(1, _settings.SendIntervalMs);


            // if not enough time passed, skip sending
            if (now - _lastSentMs < interval)
                return;

            _lastSentMs = now;

            _logger.LogInformation(
                "[WEIGHT LOG] PontId={Pont} Weight={Weight} Raw={Raw} Machine={MachineName}",
                _settings.PontId, w, raw, Environment.MachineName);

            await _signalR.BroadcastWeightAsync(
                _identity.DeviceId,
                _identity.Channel,
                _settings.PontId,
                w);
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            if (_serialPort != null && _serialPort.IsOpen)
                _serialPort.Close();

            await base.StopAsync(ct);
        }
    }
}
