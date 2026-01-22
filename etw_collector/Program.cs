using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 8765);
});

var app = builder.Build();

var collector = new EtwCollectorService();
collector.Start();

app.MapGet("/health", () => Results.Ok(new { status = "ok", diag = collector.GetDiag() }));

app.MapPost("/start", (StartRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.AnalysisId))
        return Results.BadRequest(new { error = "analysis_id is required" });

    if (string.IsNullOrWhiteSpace(req.OutputDir))
        return Results.BadRequest(new { error = "output_dir is required" });

    if (string.IsNullOrWhiteSpace(req.TargetExe))
        return Results.BadRequest(new { error = "target_exe is required" });

    try
    {
        collector.StartCapture(req.AnalysisId, req.OutputDir, req.TargetExe);
        return Results.Ok(new { status = "started" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
});

app.MapPost("/stop", (StopRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.AnalysisId))
        return Results.BadRequest(new { error = "analysis_id is required" });

    try
    {
        var stopped = collector.TryStopCapture(req.AnalysisId);
        return stopped
            ? Results.Ok(new { status = "stopped" })
            : Results.Ok(new { status = "already_stopped" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
});

app.Lifetime.ApplicationStopping.Register(() =>
{
    collector.Dispose();
});

app.Run();

record StartRequest(string AnalysisId, string OutputDir, string TargetExe);
record StopRequest(string AnalysisId);

sealed class EtwCollectorService : IDisposable
{
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, Capture> _captures = new();

    private long _procStartEvents;
    private long _fileIoEvents;
    private long _imageLoadEvents;
    private long _tcpEvents;
    private DateTime _lastEventUtc;

    private DateTime _loopStartedUtc;
    private string? _lastLoopError;

    private TraceEventSession? _session;
    private Task? _processingTask;

    private static readonly object _diagLock = new();
    private static readonly string _diagPath = Path.Combine(Path.GetTempPath(), "FileTrace", "collector_debug.log");

    private static void Diag(string message)
    {
        try
        {
            lock (_diagLock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_diagPath)!);
                File.AppendAllText(_diagPath, $"{DateTime.UtcNow:O} {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // ignore
        }
    }

    private static string RunProcess(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi);
        if (proc == null)
            return "";

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(5000);

        return string.Join("\n", new[] { stdout, stderr }.Where(s => !string.IsNullOrWhiteSpace(s)));
    }

    private static void CleanupStaleSessions()
    {
        try
        {
            var output = RunProcess("logman", "query -ets");
            if (string.IsNullOrWhiteSpace(output))
                return;

            var prefixes = new[] { "FileTraceKernelCollector" };
            var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0)
                    continue;

                var name = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                if (!prefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    continue;

                try
                {
                    RunProcess("logman", $"stop \"{name}\" -ets");
                    Diag($"CleanupStaleSessions(): stopped {name}");
                }
                catch (Exception ex)
                {
                    Diag($"CleanupStaleSessions(): stop failed {name}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Diag($"CleanupStaleSessions(): failed: {ex.Message}");
        }
    }

    public void Start()
    {
        lock (_lock)
        {
            if (_session != null)
                return;

            if (TraceEventSession.IsElevated() != true)
                throw new InvalidOperationException("EtwCollector must be run as Administrator to enable kernel providers.");

            // Use a stable session name to avoid leaking multiple kernel sessions on crashes/restarts.
            // Kernel sessions are a limited system resource; if we generate unique names each time,
            // orphaned sessions can accumulate and prevent new sessions from starting.
            var sessionName = "FileTraceKernelCollector";
            CleanupStaleSessions();
            Diag($"Start(): creating TraceEventSession name={sessionName}");
            _session = new TraceEventSession(sessionName);
            _session.StopOnDispose = true;

            var keywords = KernelTraceEventParser.Keywords.Process |
                           KernelTraceEventParser.Keywords.Thread |
                           KernelTraceEventParser.Keywords.ImageLoad |
                           KernelTraceEventParser.Keywords.FileIO |
                           KernelTraceEventParser.Keywords.FileIOInit |
                           KernelTraceEventParser.Keywords.Registry |
                           KernelTraceEventParser.Keywords.NetworkTCPIP;

            try
            {
                Diag($"Start(): EnableKernelProvider keywords={keywords}");
                _session.EnableKernelProvider(keywords);
                Diag("Start(): EnableKernelProvider OK");
            }
            catch (Exception ex)
            {
                Diag($"Start(): EnableKernelProvider FAILED: {ex}");
                if (ex is System.Runtime.InteropServices.COMException comEx && comEx.HResult == unchecked((int)0x800705AA))
                {
                    try
                    {
                        CleanupStaleSessions();
                    }
                    catch
                    {
                    }
                }
                try
                {
                    _session.Dispose();
                }
                catch
                {
                    // ignore
                }
                _session = null;
                throw;
            }

            _processingTask = Task.Run(() => ProcessLoop(_session));
            _processingTask.ContinueWith(t =>
            {
                if (t.IsFaulted)
                {
                    _lastLoopError = t.Exception?.ToString();
                    Diag($"ProcessLoop crashed: {t.Exception}");
                }
                else
                    Diag("ProcessLoop completed");
            });
        }
    }

    private void EnsureRunning()
    {
        lock (_lock)
        {
            if (_session == null)
            {
                Start();
                return;
            }

            if (_processingTask == null || _processingTask.IsCompleted || _processingTask.IsFaulted || _processingTask.IsCanceled)
            {
                try
                {
                    _session.Dispose();
                }
                catch
                {
                    // ignore
                }
                _session = null;
                Start();
            }
        }
    }

    public void StartCapture(string analysisId, string outputDir, string targetExe)
    {
        EnsureRunning();
        Directory.CreateDirectory(outputDir);

        var capture = new Capture(analysisId, outputDir, targetExe);

        if (!_captures.TryAdd(analysisId, capture))
            throw new InvalidOperationException($"Capture already exists for analysis_id={analysisId}");

        // Marker row: helps to distinguish "capture started but no kernel events" vs "capture not started".
        capture.WriteMarker("Capture", "Start");
    }

    public void StopCapture(string analysisId)
    {
        if (_captures.TryRemove(analysisId, out var capture))
        {
            capture.FinalizeFiles();
            capture.Dispose();
            return;
        }

        throw new KeyNotFoundException($"Capture not found for analysis_id={analysisId}");
    }

    public bool TryStopCapture(string analysisId)
    {
        if (_captures.TryRemove(analysisId, out var capture))
        {
            capture.FinalizeFiles();
            capture.Dispose();
            return true;
        }

        return false;
    }

    private void ProcessLoop(TraceEventSession session)
    {
        try
        {
            Diag("ProcessLoop: started");
            _loopStartedUtc = DateTime.UtcNow;
            _lastLoopError = null;

            var source = session.Source;
            var kernel = source.Kernel;

        kernel.ProcessStart += data =>
        {
            Interlocked.Increment(ref _procStartEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnProcessStart(data);
        };

        kernel.FileIORead += data =>
        {
            Interlocked.Increment(ref _fileIoEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnFileIo("Read", data);
        };

        kernel.FileIOWrite += data =>
        {
            Interlocked.Increment(ref _fileIoEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnFileIo("Write", data);
        };

        kernel.FileIOCreate += data =>
        {
            Interlocked.Increment(ref _fileIoEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnFileIo("Create", data);
        };

        kernel.FileIODelete += data =>
        {
            Interlocked.Increment(ref _fileIoEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnFileIo("Delete", data);
        };

        kernel.ImageLoad += data =>
        {
            Interlocked.Increment(ref _imageLoadEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnImageLoad(data);
        };

        kernel.TcpIpConnect += data =>
        {
            Interlocked.Increment(ref _tcpEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnTcp("Connect", data);
        };

        kernel.TcpIpSend += data =>
        {
            Interlocked.Increment(ref _tcpEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnTcp("Send", data);
        };

        kernel.TcpIpRecv += data =>
        {
            Interlocked.Increment(ref _tcpEvents);
            _lastEventUtc = DateTime.UtcNow;
            foreach (var cap in _captures.Values)
                cap.OnTcp("Recv", data);
        };

            source.Process();
            Diag("ProcessLoop: source.Process returned");
        }
        catch (Exception ex)
        {
            _lastLoopError = ex.ToString();
            Diag($"ProcessLoop exception: {ex}");
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var cap in _captures.Values)
        {
            cap.Dispose();
        }
        _captures.Clear();

        lock (_lock)
        {
            _session?.Dispose();
            _session = null;
        }

        try
        {
            _processingTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // ignore
        }
    }

    public object GetDiag()
    {
        var taskState = _processingTask == null
            ? "null"
            : _processingTask.IsFaulted
                ? "faulted"
                : _processingTask.IsCanceled
                    ? "canceled"
                    : _processingTask.IsCompleted
                        ? "completed"
                        : "running";

        return new
        {
            proc_start = Interlocked.Read(ref _procStartEvents),
            fileio = Interlocked.Read(ref _fileIoEvents),
            image_load = Interlocked.Read(ref _imageLoadEvents),
            tcp = Interlocked.Read(ref _tcpEvents),
            last_event_utc = _lastEventUtc == default ? null : _lastEventUtc.ToString("O"),
            loop_started_utc = _loopStartedUtc == default ? null : _loopStartedUtc.ToString("O"),
            loop_task_state = taskState,
            last_loop_error = _lastLoopError,
            active_captures = _captures.Count,
        };
    }
}

sealed class Capture : IDisposable
{
    private static readonly string[] CsvHeaders = new[]
    {
        "Event Name","Type","TimeStamp","Provider","Task","Opcode","Flags","Level","Keywords","PID",
        "TID","ProcessName","ImageFileName","CommandLine","Path","User Data"
    };

    private readonly string _analysisId;
    private readonly string _outputDir;
    private readonly string _targetExeLower;
    private readonly string _targetExeLowerNoExt;
    private bool _targetFound;

    private readonly HashSet<int> _trackedPids = new();
    private readonly object _writeLock = new();

    private readonly string _csvPath;
    private readonly string _jsonPath;
    private readonly string _procLogPath;

    private readonly StreamWriter _csv;
    private readonly StreamWriter _procLog;

    public Capture(string analysisId, string outputDir, string targetExe)
    {
        _analysisId = analysisId;
        _outputDir = outputDir;
        _targetExeLower = targetExe.Trim().ToLowerInvariant();
        _targetExeLowerNoExt = Path.GetFileNameWithoutExtension(_targetExeLower);

        _csvPath = Path.Combine(_outputDir, "trace.csv");
        _jsonPath = Path.Combine(_outputDir, "trace.json");
        _procLogPath = Path.Combine(_outputDir, "process_debug.log");

        _csv = new StreamWriter(new FileStream(_csvPath, FileMode.Create, FileAccess.Write, FileShare.Read), Encoding.UTF8);
        WriteCsvRow(CsvHeaders);
        _csv.Flush();

        _procLog = new StreamWriter(new FileStream(_procLogPath, FileMode.Create, FileAccess.Write, FileShare.Read), Encoding.UTF8);
        _procLog.WriteLine($"target_exe={_targetExeLower} target_exe_no_ext={_targetExeLowerNoExt}");
        _procLog.Flush();
    }

    public void WriteMarker(string eventName, string eventType)
    {
        WriteEvent(
            eventName,
            eventType,
            DateTime.UtcNow,
            0,
            0,
            "",
            "",
            "",
            "",
            $"analysis_id={_analysisId}"
        );
    }

    public void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            var procName = (data.ProcessName ?? string.Empty).ToLowerInvariant();
            var imageName = (data.ImageFileName ?? string.Empty).ToLowerInvariant();
            var cmd = (data.CommandLine ?? string.Empty).ToLowerInvariant();

            lock (_writeLock)
            {
                _procLog.WriteLine($"{data.TimeStamp:o} pid={data.ProcessID} ppid={data.ParentID} proc={procName} image={imageName} cmd={cmd}");
                _procLog.Flush();
            }

            bool cmdMatches = cmd.Contains(_targetExeLower) || cmd.Contains(_targetExeLowerNoExt);
            bool imageContains = imageName.Contains("\\" + _targetExeLower) || imageName.Contains("\\" + _targetExeLowerNoExt + ".exe");

            var matches =
                procName == _targetExeLower ||
                procName == _targetExeLowerNoExt ||
                imageName.EndsWith("\\" + _targetExeLower) ||
                imageName.EndsWith("\\" + _targetExeLowerNoExt + ".exe") ||
                cmdMatches ||
                imageContains;

            if (matches)
            {
                _targetFound = true;
                lock (_trackedPids)
                {
                    _trackedPids.Add(data.ProcessID);
                }

                WriteEvent(
                    "Process",
                    "Start",
                    data.TimeStamp,
                    data.ProcessID,
                    data.ThreadID,
                    data.ProcessName,
                    data.ImageFileName,
                    data.CommandLine,
                    "",
                    $"Parent=0x{data.ParentID:X}"
                );
                return;
            }

            // Discovery mode: until the target is detected, log all Process Start events.
            // This prevents empty trace.csv when the container starts with a different image/process name.
            if (!_targetFound)
            {
                WriteEvent(
                    "Process",
                    "Start",
                    data.TimeStamp,
                    data.ProcessID,
                    data.ThreadID,
                    data.ProcessName,
                    data.ImageFileName,
                    data.CommandLine,
                    "",
                    $"Parent=0x{data.ParentID:X}"
                );
            }

            bool isChild;
            lock (_trackedPids)
            {
                isChild = _trackedPids.Contains(data.ParentID);
                if (isChild)
                    _trackedPids.Add(data.ProcessID);
            }

            if (isChild)
                WriteEvent(
                    "Process",
                    "Start",
                    data.TimeStamp,
                    data.ProcessID,
                    data.ThreadID,
                    data.ProcessName,
                    data.ImageFileName,
                    data.CommandLine,
                    "",
                    $"Parent=0x{data.ParentID:X}"
                );
        }
        catch
        {
            // ignore
        }
    }

    public void OnImageLoad(ImageLoadTraceData data)
    {
        if (!IsTracked(data.ProcessID))
            return;

        WriteEvent("Image", "Load", data.TimeStamp, data.ProcessID, data.ThreadID, data.ProcessName, data.FileName, "", data.FileName, data.FileName);
    }

    public void OnFileIo(string op, FileIOReadWriteTraceData data)
    {
        if (!IsTracked(data.ProcessID))
            return;

        WriteEvent("FileIo", op, data.TimeStamp, data.ProcessID, data.ThreadID, data.ProcessName, "", "", data.FileName ?? string.Empty, data.FileName ?? string.Empty);
    }

    public void OnFileIo(string op, FileIOCreateTraceData data)
    {
        if (!IsTracked(data.ProcessID))
            return;

        WriteEvent("FileIo", op, data.TimeStamp, data.ProcessID, data.ThreadID, data.ProcessName, "", "", data.FileName ?? string.Empty, data.FileName ?? string.Empty);
    }

    public void OnFileIo(string op, FileIOInfoTraceData data)
    {
        if (!IsTracked(data.ProcessID))
            return;

        WriteEvent("FileIo", op, data.TimeStamp, data.ProcessID, data.ThreadID, data.ProcessName, "", "", data.FileName ?? string.Empty, data.FileName ?? string.Empty);
    }

    public void OnTcp(string op, TraceEvent data)
    {
        if (!IsTracked(data.ProcessID))
            return;

        string ud;
        try
        {
            var saddr = data.PayloadByName("saddr")?.ToString() ?? "";
            var sport = data.PayloadByName("sport")?.ToString() ?? "";
            var daddr = data.PayloadByName("daddr")?.ToString() ?? "";
            var dport = data.PayloadByName("dport")?.ToString() ?? "";
            var size = data.PayloadNames.Contains("size") ? (data.PayloadByName("size")?.ToString() ?? "") : "";

            ud = string.IsNullOrEmpty(size)
                ? $"{saddr}:{sport} -> {daddr}:{dport}"
                : $"{saddr}:{sport} -> {daddr}:{dport} size={size}";
        }
        catch
        {
            ud = data.ToString();
        }

        WriteEvent("TcpIp", op, data.TimeStamp, data.ProcessID, data.ThreadID, data.ProcessName, "", "", "", ud);
    }

    private bool IsTracked(int pid)
    {
        lock (_trackedPids)
        {
            return _trackedPids.Contains(pid);
        }
    }

    private void WriteEvent(string eventName, string eventType, DateTime timeStamp, int pid, int tid, string? processName, string? imageFileName, string? commandLine, string path, string userData)
    {
        var row = new[]
        {
            eventName,
            eventType,
            timeStamp.ToString("o", CultureInfo.InvariantCulture),
            "",
            "",
            "",
            "",
            "",
            "",
            "0x" + pid.ToString("X"),
            tid.ToString(CultureInfo.InvariantCulture),
            processName ?? string.Empty,
            imageFileName ?? string.Empty,
            commandLine ?? string.Empty,
            path,
            userData,
        };

        lock (_writeLock)
        {
            WriteCsvRow(row);
            _csv.Flush();
        }
    }

    private void WriteCsvRow(string[] row)
    {
        var escaped = row.Select(v => EscapeCsv(v)).ToArray();
        _csv.WriteLine(string.Join(",", escaped));
    }

    private static string EscapeCsv(string value)
    {
        if (value.Contains('"'))
            value = value.Replace("\"", "\"\"");
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            return "\"" + value + "\"";
        return value;
    }

    public void FinalizeFiles()
    {
        lock (_writeLock)
        {
            _csv.Flush();
        }

        try
        {
            var json = ConvertCsvToJson(_csvPath);
            File.WriteAllText(_jsonPath, json, Encoding.UTF8);
        }
        catch
        {
            // ignore
        }
    }

    private static string ConvertCsvToJson(string csvPath)
    {
        var lines = File.ReadAllLines(csvPath, Encoding.UTF8);
        if (lines.Length == 0)
            return "[]";

        var headers = ParseCsvLine(lines[0]);
        var items = new List<Dictionary<string, string>>();

        for (var i = 1; i < lines.Length; i++)
        {
            var cols = ParseCsvLine(lines[i]);
            if (cols.Count == 0)
                continue;

            var obj = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var j = 0; j < headers.Count && j < cols.Count; j++)
                obj[headers[j]] = cols[j];

            items.Add(obj);
        }

        var sb = new StringBuilder();
        sb.Append('[');
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(System.Text.Json.JsonSerializer.Serialize(items[i]));
        }
        sb.Append(']');
        return sb.ToString();
    }

    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            var c = line[i];

            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        sb.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    sb.Append(c);
                }
            }
            else
            {
                if (c == ',')
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                }
                else if (c == '"')
                {
                    inQuotes = true;
                }
                else
                {
                    sb.Append(c);
                }
            }
        }

        result.Add(sb.ToString());
        return result;
    }

    public void Dispose()
    {
        lock (_writeLock)
        {
            _csv.Dispose();
            _procLog.Dispose();
        }
    }
}
