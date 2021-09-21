namespace ChromeIPCSniffer
{
    public enum ChromeProcessType
    {
        Unknown = 0,
        Broker,
        Renderer,
        Extension,
        Notification,
        Plugin,
        Worker,
        NCAL,
        GpuProcess,
        Watcher,
        ServiceWorker,
        NetworkService,
        AudioService,
        ContentDecryptionModuleService,
        CrashpadHandler,
        PpapiBroker,
    }
}
