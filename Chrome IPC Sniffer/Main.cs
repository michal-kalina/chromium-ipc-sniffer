using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;

namespace ChromeIPCSniffer
{
    public static class Program
    {
        public static string WIRESHARK_DIR = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wireshark");
        public static string WIRESHARK_PLUGINS_DIR = Path.Combine(WIRESHARK_DIR, "Plugins");

        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.WriteLine("Chrome IPC Sniffer v" + Assembly.GetExecutingAssembly().GetName().Version.ToString());
            Console.WriteLine();

            //
            // Parse the arguments
            //
            bool onlyNewPipes = false;
            bool forceFetchInterfacesInfo = false;
            bool forceExtractMethodNames = false;
            bool onlyMojo = false;
            var customProcessName = string.Empty;
            var customIpcName = string.Empty;
            var customChromiumVersion = string.Empty;
            foreach (string argument in args)
            {
                if (argument.Contains("--update-interfaces-info")) { forceFetchInterfacesInfo = true; forceExtractMethodNames = true; }
                else if (argument.Contains("--only-new-mojo-pipes")) onlyNewPipes = true;
                else if (argument.Contains("--extract-method-names")) forceExtractMethodNames = true;
                else if (argument.Contains("--only-mojo")) onlyMojo = true;
                else if (argument.Contains("-h") || argument.Contains("--help") || argument.Contains("/?")) { ShowUsage(); return; }
                else if (argument.Contains("--custom-process-name"))
                {
                    var r1 = new Regex(@"--custom-process-name\=(?<customProcessName>.*)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                    var m1 = r1.Match(argument);
                    if (!m1.Success)
                    {
                        Console.WriteLine("[!] Unrecognized argument value '{0}'", argument);
                        return;
                    }
                    customProcessName = m1.Groups["customProcessName"].Value;
                    Console.WriteLine($"[+] Using custom process name '{customProcessName}'");
                }
                else if (argument.Contains("--custom-ipc-name"))
                {
                    var r2 = new Regex(@"--custom-ipc-name\=(?<customIpcName>.*)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                    var m2 = r2.Match(argument);
                    if (!m2.Success)
                    {
                        Console.WriteLine("[!] Unrecognized argument value '{0}'", argument);
                        return;
                    }
                    customIpcName = m2.Groups["customIpcName"].Value;
                    Console.WriteLine($"[+] Using custom ipc '{customIpcName}'");
                }
                else if (argument.Contains("--custom-chromium-version"))
                {
                    var r2 = new Regex(@"--custom-chromium-version\=(?<customChromiumVersion>.*)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                    var m2 = r2.Match(argument);
                    if (!m2.Success)
                    {
                        Console.WriteLine("[!] Unrecognized argument value '{0}'", argument);
                        return;
                    }
                    customChromiumVersion = m2.Groups["customChromiumVersion"].Value;
                    Console.WriteLine($"[+] Using chromium version '{customChromiumVersion}'");
                }
                else
                {
                    Console.WriteLine("[!] Unrecognized argument '{0}'", argument);
                    return;
                }
            }

            Console.WriteLine("Type -h to get usage help and extended options");
            Console.WriteLine();

            Console.WriteLine("[+] Starting up");

            //
            // Prepare
            //

            IMonitor monitor = null;
            if (string.IsNullOrEmpty(customProcessName) && 
                string.IsNullOrEmpty(customChromiumVersion) &&
                string.IsNullOrEmpty(customIpcName))
                monitor = new ChromeMonitor();
            else
                monitor = new CustomMonitor(customProcessName, customChromiumVersion, customIpcName);
            var mojoVersion = MojoInterfacesFetcher.UpdateInterfacesInfoIfNeeded(monitor, force: forceFetchInterfacesInfo);
            var legacyIpcVersion = LegacyIpcInterfacesFetcher.UpdateInterfacesInfoIfNeeded(monitor, force: forceFetchInterfacesInfo);
            if (mojoVersion != monitor.ChromeVersion || legacyIpcVersion != monitor.ChromeVersion)
            {
                Console.WriteLine("[!] Cached info is for " + mojoVersion + ", you may run --update-interfaces-info");
            }

            //MojoMethodHashesExtractor.ExtractMethodNames(monitor.DLLPath, force: forceExtractMethodNames);

            bool success = UpdateWiresharkConfiguration();
            if (!success) return;

            Console.WriteLine("[+] Enumerating existing chrome pipes");
            HandlesUtility.EnumerateExistingHandles(monitor.GetRunningProcesses());

            //
            // Start sniffing
            //

            string outputPipeName = monitor.OutputPipeName;
            string outputPipePath = @"\\.\pipe\" + outputPipeName;
            Console.WriteLine("[+] Starting sniffing of chrome named pipe to " + outputPipePath + ".");

            NamedPipeSniffer pipeMonitor = new NamedPipeSniffer(monitor, outputPipeName, onlyMojo ? "mojo" : "", onlyNewPipes);
            bool isMonitoring = pipeMonitor.Start();

            if (isMonitoring)
            {
                if (Process.GetProcessesByName("Wireshark").Length == 0)
                {
                    Console.WriteLine("[+] Opening Wirehark");
                    Process.Start(@"C:\Program Files\Wireshark\Wireshark.exe", "-k -i " + outputPipePath);
                }

                Console.WriteLine("[+] Capturing packets...");
            }

            //
            // Set up clean up routines
            //
            Console.CancelKeyPress += delegate
            {
                Thread.CurrentThread.IsBackground = false;
                pipeMonitor.Stop();
            };

        }

        static void ShowUsage()
        {
            Console.WriteLine(
            @"Syntax: chromeipc [options]
Available options:

    Capturing:
        --only-mojo
            Records only packets sent over a ""\\mojo.*"" pipe (without ""\\chrome.sync.*"", etc.).

        --only-new-mojo-pipes
            Records only packets sent over mojo AND newly-created pipes since the start of the capture
            This helps reducing noise and it might improve performance
            (example: opening a new tab will create a new mojo pipe).
            
    Interface resolving:
        --update-interfaces-info
            Forcefully re-scan the chromium sources (from the internet) and populate the *_interfaces.json files.
            This might take a few good minutes. Use this if you see wrong interfaces info and wish to update

        --extract-method-names
            Forcefully re-scan chrome.dll file to find the message IDs and update the mojo_interfaces_map.lua file
            This should happen automaticlly whenever chrome.dll changes.

    Custom monitor:
        All below switches has to be provided otherwise default chrome sniffer will be used.
        --custom-process-name
            Using: --custom-process-name=""<Name of a process you want to monitor (without .exe part)>"".
            Example: --custom-process-name=""chrome"" 
        --custom-chromium-version
            Using: --custom-chromium-version ""<chromium-version>""
            Example: --custom-chromium-version ""87.0.4280.141""
        --custom-ipc-name
            Using: --custom-ipc-name ""<ipc-name>""
            Example: --custom-ipc-name ""chromiumipc""
                            ");

        }

        static bool UpdateWiresharkConfiguration()
        {
            if (!Directory.Exists(WIRESHARK_DIR))
            {
                Console.WriteLine("[-] Could not find Wireshark data directory at " + WIRESHARK_DIR);
                Console.WriteLine("[-] Make sure you have Wireshark installed.");

                return false;
            }
            else if (!Directory.Exists(WIRESHARK_PLUGINS_DIR))
            {
                // We should probably just create the plugins directory
                Directory.CreateDirectory(WIRESHARK_PLUGINS_DIR);
            }

            Console.WriteLine("[+] Copying LUA dissectors to Wirehsark plugins directory");

            DirectoryExtensions.CopyDirectory("Dissectors", WIRESHARK_PLUGINS_DIR, true);

            //
            // Configure protocol colors
            //
            string colorfiltersFile = Path.Combine(WIRESHARK_DIR, "colorfilters");
            if (!File.Exists(colorfiltersFile)) colorfiltersFile = @"C:\Program Files\Wireshark\colorfilters";
            if (!File.Exists(colorfiltersFile))
            {
                Console.WriteLine("[!] Could not find Wireshark's colorfilters file, skipping color configuration");

                return true;
            }

            if (!File.ReadAllText(colorfiltersFile).Contains("@mojouser"))
            {
                Console.WriteLine("[+] Configuring Wirehsark protocol colors");

                try
                {
                    File.AppendAllText(colorfiltersFile,
                        @"@Mojo Data@mojodata@[65278,65535,53456][0,0,0]
    @Legacy IPC@legacyipc@[64764,57568,65535][0,0,0]
    @Mojo User@mojouser@[56026,61166,65535][0,0,0]
    @Mojo@mojo@[58596,65535,51143][0,0,0]
    @NPFS@npfs@[59367,59110,65535][0,0,0]");
                }
                catch (Exception)
                {
                    Console.WriteLine("[!] Could not edit colorfilters, skipping.");
                }
            }

            return true;
        }
    }
}
