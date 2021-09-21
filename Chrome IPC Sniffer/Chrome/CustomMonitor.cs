using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace ChromeIPCSniffer
{
    public class CustomMonitor : IMonitor
    {
        // This should be updated whenever a chrome process gets created/destryoed
        private Dictionary<UInt32, ProcessInfo> RunningProcessesCache = new Dictionary<UInt32, ProcessInfo>();

        public string DllPath { get; protected set; } = string.Empty;
        public string ChromeVersion { get; protected set; } = string.Empty;
        public string OutputPipeName { get; protected set; } = string.Empty;
        public string ProcessName { get; protected set; } = string.Empty;

        public CustomMonitor(string processName, string chromiumVersion, string ipcName)
        {
            this.ChromeVersion = chromiumVersion;
            this.OutputPipeName = ipcName;
            this.ProcessName = processName;

            UpdateRunningProcessesCache();
            InitializeInstance();
        }

        protected virtual void InitializeInstance(string dllPath = null)
        {
            Console.WriteLine("[+] Determining your Chromium version");
            this.DllPath = GetDLLPath();

            Console.WriteLine("[+] You are using Chromium " + this.ChromeVersion);
            Console.WriteLine("[+] " + this.DllPath);
        }

        public List<int> GetRunningPIDs()
        {
            return RunningProcessesCache.Values.Where(processInfo => processInfo.Name.Contains(this.ProcessName)).Select(processInfo => processInfo.PID).ToList();
        }

        public void UpdateRunningProcessesCache()
        {
            var runningProcesses = Process.GetProcesses();
            foreach (var process in runningProcesses)
            {
                ProcessInfo processInfo;
                processInfo.PID = process.Id;
                processInfo.Name = process.ProcessName;
                processInfo.CommandLine = processInfo.Name == this.ProcessName ? process.GetCommandLine() : "";
                RunningProcessesCache[(UInt32)process.Id] = processInfo;
            }
        }

        public bool IsProcess(UInt32 pid)
        {
            if (RunningProcessesCache.ContainsKey(pid))
            {
                return RunningProcessesCache[pid].Name == this.ProcessName;
            }
            return false;
        }

        public ChromeProcessType GetProcessType(UInt32 chromePID)
        {
            string commandLine = null;
            string processName = null;

            if (!RunningProcessesCache.ContainsKey(chromePID))
            {
                return ChromeProcessType.Unknown;
            }
            commandLine = RunningProcessesCache[chromePID].CommandLine;
            processName = RunningProcessesCache[chromePID].Name;

            var type = ChromeProcessType.Unknown;

            // Some sanity checks
            if (processName != this.ProcessName) return type;
            if (commandLine == null) return type;

            if (!commandLine.Contains("--type=")) type = ChromeProcessType.Broker;
            else if (commandLine.Contains("--extension-process") && !commandLine.Contains("--disable-databases")) type = ChromeProcessType.Extension;
            else if (commandLine.Contains("--type=watcher")) type = ChromeProcessType.Watcher;
            //else if (commandLine.Contains("--service-sandbox-type=audio")) type = ChromeProcessType.AudioService;
            else if (commandLine.Contains("--service-sandbox-type=network")) type = ChromeProcessType.NetworkService;
            else if (commandLine.Contains("--service-sandbox-type=cdm")) type = ChromeProcessType.ContentDecryptionModuleService;
            else if (commandLine.Contains("--type=gpu-process")) type = ChromeProcessType.GpuProcess;
            else if (commandLine.Contains("--type=renderer")) type = ChromeProcessType.Renderer;

            return type;
        }

        private bool ProcessExists(UInt32 pid)
        {
            UpdateRunningProcessesCache();

            return RunningProcessesCache.ContainsKey(pid);
        }

        public Process[] GetRunningProcesses()
        {
            return Process.GetProcessesByName(this.ProcessName);
        }

        public virtual string GetDLLPath()
        {
            return "";
        }

        public string GetCommitForVersion()
        {
            WebClient webClient = new WebClient();
            webClient.Headers.Add("User-Agent", $"Chrome {this.ChromeVersion} IPC Sniffer");

            dynamic commits = JsonConvert.DeserializeObject(webClient.DownloadString("https://api.github.com/repos/chromium/chromium/git/refs/tags/" + this.ChromeVersion));
            string commit = commits["object"]["sha"];
            return commit;
        }
    }
}
