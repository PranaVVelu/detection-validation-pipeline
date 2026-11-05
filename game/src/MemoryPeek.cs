// Requests a handle to another process, then closes it. It never reads or writes
// memory: requesting the handle is the behavior the pipeline needs to observe.
using System;
using System.Globalization;
using System.Runtime.InteropServices;

internal static class MemoryPeek
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static int Main(string[] args)
    {
        int processId = int.Parse(args[0]);
        uint access = uint.Parse(args[1].Replace("0x", ""), NumberStyles.HexNumber);

        IntPtr handle = OpenProcess(access, false, processId);
        if (handle == IntPtr.Zero)
        {
            Console.Error.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error());
            return 1;
        }
        CloseHandle(handle);
        Console.WriteLine("Opened and closed process " + processId + " with access " + args[1]);
        return 0;
    }
}
