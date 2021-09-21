using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;

namespace ChromeIPCSniffer
{
    public class ChromeMonitor : CustomMonitor
    {
        public ChromeMonitor(string dllPath = null)
            : base("chrome", string.Empty, "chromiumipc")
        {
            UpdateRunningProcessesCache();
            InitializeInstance(dllPath);
        }

        protected override void InitializeInstance(string dllPath = null)
        {
            Console.WriteLine("[+] Determining your chromium version");
            this.DllPath = dllPath ?? GetDLLPath();
            this.ChromeVersion = new DirectoryInfo(Path.GetDirectoryName(this.DllPath) ?? string.Empty).Name;

            Console.WriteLine("[+] You are using chromium " + this.ChromeVersion);
        }

        public override string GetDLLPath()
        {
            //
            // Search for a chrome process that has chrome.dll loaded in
            //
            try
            {
                foreach (var chromeProcess in Process.GetProcessesByName(this.ProcessName))
                {
                    var chromeModules = chromeProcess.Modules;
                    foreach (ProcessModule module in chromeModules)
                    {
                        if (module.FileName.EndsWith("chrome.dll"))
                        {
                            return module.FileName;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // well, try to use the fallback method.
            }

            //
            // Look in Program Fies manually.
            //

            var programFilesDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application");

            if (Directory.Exists(programFilesDir))
            {
                List<Version> chromeVersions = new DirectoryInfo(programFilesDir).GetDirectories().Where(info => info.Name.Contains("."))
                    .Select(info => new Version(info.Name)).ToList();

                chromeVersions.Sort();
                chromeVersions.Reverse();

                var chromeDllPath = Path.Combine(programFilesDir, chromeVersions[0].ToString(), "chrome.dll");
                if (File.Exists(chromeDllPath)) return chromeDllPath;
            }

            Console.WriteLine("[-] Could not find chrome.dll. Aborting.");
            Environment.Exit(1);

            return "";
        }
    }
}
