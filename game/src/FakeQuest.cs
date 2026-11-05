// A harmless stand-in for a real game, so game security rules have something to
// protect. It pretends to check a license, then idles like a running game. It
// contains no real DRM, and it never contacts anything.
using System;
using System.Runtime.InteropServices;
using System.Threading;

internal static class FakeQuest
{
    // Importing from winmm.dll makes Windows load it by name, which is how real
    // games pick up a planted copy from their own folder. It can't be version.dll:
    // real logs show the .NET runtime loads that from System32 before Main runs, so
    // a planted copy is never used.
    [DllImport("winmm.dll")]
    private static extern uint timeGetTime();

    private static int Main(string[] args)
    {
        int seconds = args.Length > 0 ? int.Parse(args[0]) : 2;
        timeGetTime();

        Console.WriteLine("FakeQuest: license check passed (this is a stub).");
        Thread.Sleep(TimeSpan.FromSeconds(seconds));
        return 0;
    }
}
