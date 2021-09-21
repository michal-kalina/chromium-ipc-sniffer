using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace ChromeIPCSniffer
{
    public interface IMonitor
    {
        string DllPath { get; }
        string ChromeVersion { get; }
        string OutputPipeName { get; }

        List<int> GetRunningPIDs();
        void UpdateRunningProcessesCache();
        bool IsProcess(UInt32 pid);
        ChromeProcessType GetProcessType(UInt32 chromePID);
        Process[] GetRunningProcesses();
        string GetDLLPath();
        string GetCommitForVersion();
    }
}