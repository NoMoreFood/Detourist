using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Xml;
#if NET10_0
using System.Runtime.Intrinsics;
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif

internal struct ManagedLayoutValue
{
    public DateTimeOffset Timestamp;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ManagedArrayPadded
{
    public int Number;
    public byte Tag;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct ManagedArrayPacked
{
    public int Number;
    public byte Tag;
}

[StructLayout(LayoutKind.Explicit, Size = 32)]
internal struct ManagedArraySized
{
    [FieldOffset(0)] public int Number;
    [FieldOffset(8)] public byte Tag;
}

internal struct ManagedArrayEmpty { }

#if NET10_0
internal struct ManagedArrayReference
{
    public object Reference;
    public long Number;
}
#endif

internal static class ManagedTarget
{
    private static int failures;
    private static int movedBuffers;
    private static int repetitions = 12;
    private delegate int ArrayElementSize();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetFileAttributesW(string path);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern void Sleep(uint milliseconds);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQuerySystemTime(out long systemTime);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleW(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint protection, out uint previous);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileW(string source, string destination);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKeyboardState([Out] byte[] keys);

    [DllImport("win32u.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool NtUserGetKeyboardState([Out] byte[] keys);

    [DllImport("win32u.dll", EntryPoint = "NtUserGetKeyboardState", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool NativeKeyboardProbe([Out] byte[] keys);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int NativeTime(out long systemTime);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int PrivateDelay(byte alertable, ref long interval);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int PrivateQuery(IntPtr process, IntPtr address, int informationClass, IntPtr buffer,
        UIntPtr length, out UIntPtr returned);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate short RawKeyState(int key);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int RawBitmapBits(IntPtr bitmap, int size, IntPtr buffer);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int RawWindowPrint(IntPtr window);

    [DllImport("gdi32.dll", ExactSpelling = true)]
    private static extern IntPtr CreateBitmap(int width, int height, uint planes, uint bits, byte[] data);

    [DllImport("gdi32.dll", ExactSpelling = true)]
    private static extern bool DeleteObject(IntPtr bitmap);


    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime
    {
        internal ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
    }

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpTimeToSystemTime(string text, out SystemTime time);

    private sealed class GcReadStream : Stream
    {
        private byte[] garbage = new byte[8192];
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        {
            // Reclaim an earlier allocation so a live output buffer moves during the framework call.
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            var before = handle.AddrOfPinnedObject();
            handle.Free();
            GC.KeepAlive(garbage);
            garbage = null;
#if LEGACY_CLR
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced);
#else
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
#endif
            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            if (handle.AddrOfPinnedObject() != before) Interlocked.Increment(ref movedBuffers);
            handle.Free();
            for (var index = offset; index < offset + count; ++index) buffer[index] = 0x6B;
            return count;
        }
    }

    private static int Main(string[] arguments)
    {
#if NET48
        if (arguments.Length == 2 && arguments[1] == "--com-images")
            return ManagedImageCapture.Run(arguments[0]);
#endif
        if (arguments.Length == 2 &&
            (arguments[1] == "--arrays-debugger" || arguments[1] == "--arrays-debugger-copy" ||
                arguments[1] == "--arrays-debugger-generic"))
        {
            // Keep the debugger workload focused on array replacement and observable value bytes.
            var copyingArrays = arguments[1] == "--arrays-debugger-copy";
            var genericArrays = arguments[1] == "--arrays-debugger-generic";
            var padded = new[] { new ManagedArrayPadded { Number = 100, Tag = 7 },
                new ManagedArrayPadded { Number = 200, Tag = 9 }, new ManagedArrayPadded { Number = 100, Tag = 7 } };
            var packed = new[] { new ManagedArrayPacked { Number = 100, Tag = 7 },
                new ManagedArrayPacked { Number = 200, Tag = 9 }, new ManagedArrayPacked { Number = 100, Tag = 7 } };
            var sized = new[] { new ManagedArraySized { Number = 100, Tag = 7 },
                new ManagedArraySized { Number = 200, Tag = 9 }, new ManagedArraySized { Number = 100, Tag = 7 } };
            var empty = new ManagedArrayEmpty[3];
            var days = new[] { DayOfWeek.Monday, DayOfWeek.Friday, DayOfWeek.Monday };
            var texts = new[] { new string('a', 3), new string('b', 3), null };
            var objects = new[] { new object(), null, new object() };
            var paddedList = genericArrays ? new List<ManagedArrayPadded>(padded) : null;
            var packedList = genericArrays ? new List<ManagedArrayPacked>(packed) : null;
            var textList = genericArrays ? new List<string>(texts) : null;
            var copiedPadded = new ManagedArrayPadded[5];
            var copiedPacked = new ManagedArrayPacked[5];
            var copiedTexts = new string[5];
            Array.Resize(ref padded, 3);
            Array.Resize(ref packed, 3);
            Array.Resize(ref sized, 3);
            Array.Resize(ref empty, 3);
            Array.Resize(ref days, 3);
            if (genericArrays)
            {
                Array.Resize(ref texts, 3);
                Array.Resize(ref objects, 3);
                paddedList.CopyTo(0, copiedPadded, 1, 0);
                packedList.CopyTo(0, copiedPacked, 1, 0);
                textList.CopyTo(0, copiedTexts, 1, 0);
            }
            var destinations = new Array[] { new ManagedArrayPadded[4], new ManagedArrayPacked[4],
                new ManagedArraySized[4], new ManagedArrayEmpty[4], new DayOfWeek[4] };
            var emptyArrays = copyingArrays ? new Array[] { new ManagedArrayPadded[0], new ManagedArrayPacked[0],
                new ManagedArraySized[0], new ManagedArrayEmpty[0], new DayOfWeek[0], new string[0],
                new object[0], new int[0][], new KeyValuePair<object, long>[0],
                Array.CreateInstance(typeof(ManagedArrayPacked), new[] { 0, 2 }, new[] { -1, 3 }) } : new Array[0];
            var emptyCopies = new Array[emptyArrays.Length];
            for (var index = 0; index < emptyArrays.Length; ++index)
                emptyCopies[index] = (Array)emptyArrays[index].Clone();
            if (copyingArrays) Array.Copy(padded, destinations[0], 0);
            File.WriteAllText(arguments[0] + ".ready", "ready");
            while (GetFileAttributesW(arguments[0] + ".go") == uint.MaxValue) Sleep(20);
            if (copyingArrays)
            {
                // The initial IL breakpoint must retain an empty array's runtime stride too.
                for (var index = 0; index < emptyArrays.Length; ++index)
                    Array.Copy(emptyArrays[index], emptyCopies[index], 0);
                Array.Copy(padded, destinations[0], 3);
                Array.Copy(packed, destinations[1], 3);
                Array.Copy(sized, destinations[2], 3);
                Array.Copy(empty, destinations[3], 3);
                Array.Copy(days, destinations[4], 3);
                padded = (ManagedArrayPadded[])destinations[0];
                packed = (ManagedArrayPacked[])destinations[1];
                sized = (ManagedArraySized[])destinations[2];
                empty = (ManagedArrayEmpty[])destinations[3];
                days = (DayOfWeek[])destinations[4];
            }
            else
            {
                Array.Resize(ref padded, 4);
                Array.Resize(ref packed, 4);
                Array.Resize(ref sized, 4);
                Array.Resize(ref empty, 4);
                Array.Resize(ref days, 4);
            }
            if (genericArrays)
            {
                Array.Resize(ref texts, 5);
                Array.Resize(ref objects, 6);
                paddedList.CopyTo(0, copiedPadded, 1, 3);
                packedList.CopyTo(0, copiedPacked, 1, 3);
                textList.CopyTo(0, copiedTexts, 1, 3);
                if (texts.Length != 5 || texts[0] != "aaa" || texts[1] != "bbb" ||
                    texts[2] != null || texts[4] != null || objects.Length != 6 || objects[0] == null ||
                    objects[1] != null || objects[2] == null || objects[5] != null ||
                    copiedPadded[2].Number != 200 || copiedPacked[2].Number != 200 ||
                    copiedTexts[1] != "aaa" || copiedTexts[2] != "bbb" || copiedTexts[4] != null) ++failures;
            }
            if (padded.Length != 4 || packed.Length != 4 || sized.Length != 4 || empty.Length != 4 ||
                days.Length != 4 || padded[1].Number != 200 || packed[1].Number != 200 ||
                sized[1].Number != 200 || days[1] != DayOfWeek.Friday)
                ++failures;
            File.WriteAllText(arguments[0] + ".complete", failures == 0 ? "arrays-ok" : "arrays-failed");
            if (!MoveFileW(arguments[0] + ".complete", arguments[0])) return 1;
            while (GetFileAttributesW(arguments[0] + ".release") == uint.MaxValue) Sleep(20);
            return failures;
        }
        if (arguments.Length == 2 && arguments[1] == "--layouts-attach")
        {
            // Warm the same value-type calls before attachment and retain the process until capture stops.
            ExerciseLayouts(null, false);
            File.WriteAllText(arguments[0] + ".ready", "ready");
            while (GetFileAttributesW(arguments[0] + ".go") == uint.MaxValue) Sleep(20);
            ExerciseLayouts(null, false);
            File.WriteAllText(arguments[0] + ".complete", failures == 0 ? "layouts-ok" : "layouts-failed");
            File.Move(arguments[0] + ".complete", arguments[0]);
            while (GetFileAttributesW(arguments[0] + ".release") == uint.MaxValue) Sleep(20);
            return failures;
        }
        if (arguments.Length == 2 && (arguments[1] == "--arrays" || arguments[1] == "--arrays-attach"))
        {
            var attachingArrays = arguments[1] == "--arrays-attach";
            if (attachingArrays)
            {
                if (Main(new[] { arguments[0] + ".warmup", "--arrays" }) != 0) return failures;
                File.WriteAllText(arguments[0] + ".ready", "ready");
                while (GetFileAttributesW(arguments[0] + ".go") == uint.MaxValue) Sleep(20);
            }
            var sizes = new[]
            {
                ExerciseArray(new ManagedArrayPadded { Number = 100, Tag = 7 },
                    new ManagedArrayPadded { Number = 200, Tag = 9 }),
                ExerciseArray(new ManagedArrayPacked { Number = 100, Tag = 7 },
                    new ManagedArrayPacked { Number = 200, Tag = 9 }),
                ExerciseArray(new ManagedArraySized { Number = 100, Tag = 7 },
                    new ManagedArraySized { Number = 200, Tag = 9 }),
                ExerciseArray(new ManagedArrayEmpty(), new ManagedArrayEmpty()),
                ExerciseArray(DayOfWeek.Monday, DayOfWeek.Friday)
            };
            var source = Array.CreateInstance(typeof(ManagedArrayPacked), new[] { 2, 2 }, new[] { -3, 5 });
            var destination = Array.CreateInstance(typeof(ManagedArrayPacked), new[] { 2, 2 }, new[] { -3, 5 });
            for (var index = 0; index < 4; ++index)
                source.SetValue(new ManagedArrayPacked { Number = 100 * (index + 1), Tag = (byte)(7 + index * 2) },
                    -3 + index / 2, 5 + index % 2);
            Array.Copy(source, destination, 4);
            if (((ManagedArrayPacked)destination.GetValue(-2, 6)).Number != 400) ++failures;
#if NET10_0
            ExerciseRuntimeArrays();
#endif
            File.WriteAllText(arguments[0] + ".complete", (failures == 0 ? "arrays-ok" : "arrays-failed") + "\n" +
                string.Join("\n", sizes));
            File.Move(arguments[0] + ".complete", arguments[0]);
            if (attachingArrays)
                while (GetFileAttributesW(arguments[0] + ".release") == uint.MaxValue) Sleep(20);
            return failures;
        }
        if (arguments.Length == 2 && (arguments[1] == "--layouts" || arguments[1] == "--layouts-lifecycle"))
        {
            try { ExerciseLayouts(arguments[1] == "--layouts-lifecycle" ? arguments[0] : null); }
            catch (Exception exception)
            {
                File.WriteAllText(arguments[0], exception.ToString());
                return 1;
            }
            File.WriteAllText(arguments[0], failures == 0 ? "layouts-ok" : "layouts-failed");
            return failures;
        }
        if (arguments.Length == 3 && arguments[1] is "--private-syscall" or "--private-syscall-fs")
            return ExercisePrivateSyscall(arguments[0], int.Parse(arguments[2], CultureInfo.InvariantCulture),
                arguments[1] == "--private-syscall-fs");
        if (arguments.Length == 4 && arguments[1] == "--private-gateways")
            return ExercisePrivateGateways(arguments[0], int.Parse(arguments[2], CultureInfo.InvariantCulture),
                int.Parse(arguments[3], CultureInfo.InvariantCulture));
        if (arguments.Length < 1 || arguments.Length > 2) return 2;
        if (arguments.Length == 2 && arguments[1] == "--raw-native")
            return ExerciseRawNative(arguments[0]);
        if (arguments.Length == 2 && arguments[1] == "--native-boundary")
            return ExerciseNativeBoundary(arguments[0]);
        var smoke = arguments.Length == 2 && arguments[1] == "--attach-smoke";
        var attaching = arguments.Length == 2 && (arguments[1] == "--attach" || smoke);
        if (smoke) repetitions = 1;
        if (attaching)
        {
            // Warm compiled framework calls before a profiler exists, then wait for the capture to attach.
            ExerciseFramework();
            File.WriteAllText(arguments[0] + ".ready", "ready");
            var go = arguments[0] + ".go";
            while (GetFileAttributesW(go) == uint.MaxValue) Sleep(20);
            failures = movedBuffers = 0;
        }
        var profiler = Environment.GetEnvironmentVariable("COR_PROFILER");
        if (!string.IsNullOrEmpty(profiler))
        {
            var key = "HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\" + profiler + "\\InprocServer32";
            if (!(Microsoft.Win32.Registry.GetValue(key, null, null) is string))
                Interlocked.Increment(ref failures);
#if !LEGACY_CLR
            // Child runtimes resolve the same profiler identity through their own registry view.
            var siblingPath = Environment.GetEnvironmentVariable(IntPtr.Size == 8 ?
                "COR_PROFILER_PATH_32" : "COR_PROFILER_PATH_64");
            if (!string.IsNullOrEmpty(siblingPath) && File.Exists(siblingPath))
            {
                using var user = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.CurrentUser, IntPtr.Size == 8 ?
                        Microsoft.Win32.RegistryView.Registry32 : Microsoft.Win32.RegistryView.Registry64);
                using var server = user.OpenSubKey("Software\\Classes\\CLSID\\" + profiler + "\\InprocServer32");
                if (!string.Equals(server?.GetValue(null) as string, siblingPath, StringComparison.OrdinalIgnoreCase))
                    Interlocked.Increment(ref failures);
            }
#endif
            File.WriteAllText(arguments[0] + ".profiler", profiler);
        }
        var workers = new Thread[3];
        for (var index = 0; index < workers.Length; ++index)
        {
            workers[index] = new Thread(ExerciseFramework);
            workers[index].Start();
        }
        foreach (var worker in workers) worker.Join();

        // Report the real provider image base because managed procedure lookup can return a capture adapter.
        File.WriteAllText(arguments[0] + ".native-site",
            GetModuleHandleW("win32u.dll").ToInt64().ToString(CultureInfo.InvariantCulture));
        if (movedBuffers == 0) Interlocked.Increment(ref failures);
        if (failures != 0)
            Console.Error.WriteLine("Framework checks failed: {0}; moved buffers: {1}; profiler: {2}",
                failures, movedBuffers, profiler ?? "<none>");
        File.WriteAllText(arguments[0] + ".complete", failures == 0 ? "managed-ok" : "managed-failed");
        File.Move(arguments[0] + ".complete", arguments[0]);
        if (attaching)
        {
            // Native coordination avoids generating framework calls while the harness is attaching or detaching.
            var release = arguments[0] + ".release";
            while (GetFileAttributesW(release) == uint.MaxValue) Sleep(20);
            ExerciseFramework();
            if ((File.GetAttributes(arguments[0]) & FileAttributes.Directory) != 0)
                Interlocked.Increment(ref failures);
        }
        return failures;
    }

    private static int ExerciseRawNative(string result)
    {
        // Resolve real native exports before attachment so the tracer must discover cached call targets.
        var module = GetModuleHandleW("win32u.dll");
        var key = (RawKeyState)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(module, "NtUserGetAsyncKeyState"), typeof(RawKeyState));
        var synchronous = (RawKeyState)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(module, "NtUserGetKeyState"), typeof(RawKeyState));
        var bits = (RawBitmapBits)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(module, "NtGdiGetBitmapBits"), typeof(RawBitmapBits));
        var user = LoadLibraryW("user32.dll");
        if (user == IntPtr.Zero) return 4;
        var redirected = (RawWindowPrint)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(user, "IsWindowRedirectedForPrint"), typeof(RawWindowPrint));
        var pattern = new byte[128];
        for (var index = 0; index < pattern.Length; ++index) pattern[index] = (byte)(index + 0x31);
        var bitmap = CreateBitmap(8, 8, 1, 16, pattern);
        var pixels = Marshal.AllocHGlobal(128);
        try
        {
            if (bitmap == IntPtr.Zero) return 1;
            for (var phase = 0; phase < 3; ++phase)
            {
                if (phase != 0)
                    while (GetFileAttributesW(result + (phase == 1 ? ".go" : ".again")) == uint.MaxValue) Sleep(20);
                var value = key(0x10);
                var state = synchronous(0x10);
                var bytes = bits(bitmap, 128, pixels);
                if (redirected(IntPtr.Zero) != 0) return 5;
                if (bytes != 128)
                {
                    Console.Error.WriteLine("Raw probe: bitmap bytes={0}", bytes);
                    return 2;
                }
                var copied = new byte[128];
                Marshal.Copy(pixels, copied, 0, copied.Length);
                for (var index = 0; index < copied.Length; ++index)
                    if (copied[index] != pattern[index]) return 3;
                var output = phase == 0 ? result + ".ready" : result + (phase == 1 ? ".first" : ".second");
                File.WriteAllText(output + ".pending", value.ToString(CultureInfo.InvariantCulture) + "|" +
                    state.ToString(CultureInfo.InvariantCulture) + "|" + Convert.ToBase64String(copied));
                File.Move(output + ".pending", output);
            }
            while (GetFileAttributesW(result + ".release") == uint.MaxValue) Sleep(20);
            return 0;
        }
        finally
        {
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            Marshal.FreeHGlobal(pixels);
        }
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern IntPtr NtCurrentTeb();

    private static byte[] PrivateSyscallCode(int number, int stackBytes, bool legacyGate = false)
    {
        if (IntPtr.Size == 8)
            return new byte[] { 0x4C, 0x8B, 0xD1, 0xB8, (byte)number, (byte)(number >> 8),
                (byte)(number >> 16), (byte)(number >> 24), 0x0F, 0x05, 0xC3 };

        // Native x86 and WOW64 preserve their own service gate and stdcall argument cleanup.
        var code = new List<byte> { 0xB8, (byte)number, (byte)(number >> 8),
            (byte)(number >> 16), (byte)(number >> 24) };
        var gate = Marshal.ReadIntPtr(NtCurrentTeb(), 0xC0);
        if (gate != IntPtr.Zero && legacyGate)
            code.AddRange(new byte[] { 0x64, 0xFF, 0x15, 0xC0, 0, 0, 0 });
        else if (gate != IntPtr.Zero)
        {
            code.Add(0xBA);
            code.AddRange(BitConverter.GetBytes(gate.ToInt32()));
            code.AddRange(new byte[] { 0xFF, 0xD2 });
        }
        else code.AddRange(new byte[] { 0xBA, 0, 3, 0xFE, 0x7F, 0xFF, 0x12 });
        code.AddRange(new byte[] { 0xC2, (byte)stackBytes, (byte)(stackBytes >> 8) });
        return code.ToArray();
    }

    private static int ExercisePrivateSyscall(string result, int number, bool legacyGate = false)
    {
        // Execute a private syscall page from managed code after the observer attaches.
        var code = PrivateSyscallCode(number, 8, legacyGate);
        var page = VirtualAlloc(IntPtr.Zero, new UIntPtr(4096), 0x3000, 0x04);
        if (page == IntPtr.Zero) return 3;
        try
        {
            Marshal.Copy(code, 0, page, code.Length);
            uint previous;
            if (!VirtualProtect(page, new UIntPtr(4096), 0x20, out previous)) return 4;
            var delay = (PrivateDelay)Marshal.GetDelegateForFunctionPointer(page, typeof(PrivateDelay));
            File.WriteAllText(result + ".ready.pending", page.ToInt64().ToString(CultureInfo.InvariantCulture));
            File.Move(result + ".ready.pending", result + ".ready");
            while (GetFileAttributesW(result + ".go") == uint.MaxValue) Sleep(20);
            var status = 0;
            for (var index = 0; index < 3; ++index)
            {
                long interval = -10000;
                status |= delay(0, ref interval);
            }
            File.WriteAllText(result + ".complete", status.ToString(CultureInfo.InvariantCulture));
            File.Move(result + ".complete", result);
            while (GetFileAttributesW(result + ".release") == uint.MaxValue) Sleep(20);
            return status;
        }
        finally
        {
            VirtualFree(page, UIntPtr.Zero, 0x8000);
        }
    }

    private static int ExercisePrivateGateways(string result, int delayNumber, int queryNumber)
    {
        var page = VirtualAlloc(IntPtr.Zero, new UIntPtr(4096), 0x3000, 0x04);
        if (page == IntPtr.Zero) return 3;
        try
        {
            // Exercise register and stack arguments through independently cached private syscall delegates.
            var offset = 0;
            foreach (var number in new[] { delayNumber, queryNumber })
            {
                var code = PrivateSyscallCode(number, offset == 0 ? 8 : 24);
                Marshal.Copy(code, 0, new IntPtr(page.ToInt64() + offset), code.Length);
                offset += 64;
            }
            uint previous;
            if (!VirtualProtect(page, new UIntPtr(4096), 0x20, out previous)) return 4;
            var delay = (PrivateDelay)Marshal.GetDelegateForFunctionPointer(page, typeof(PrivateDelay));
#if LEGACY_CLR
            var alternate = (PrivateDelay)Marshal.GetDelegateForFunctionPointer(page, typeof(PrivateDelay));
            var query = (PrivateQuery)Marshal.GetDelegateForFunctionPointer(new IntPtr(page.ToInt64() + 64),
                typeof(PrivateQuery));
#else
            var alternate = Marshal.GetDelegateForFunctionPointer<PrivateDelay>(page);
            var query = Marshal.GetDelegateForFunctionPointer<PrivateQuery>(new IntPtr(page.ToInt64() + 64));
#endif
            RawWindowPrint callback = value => value.ToInt32() + 1;
            var callbackPointer = Marshal.GetFunctionPointerForDelegate(callback);
            File.WriteAllText(result + ".ready.pending", page.ToInt64().ToString(CultureInfo.InvariantCulture));
            File.Move(result + ".ready.pending", result + ".ready");
            var status = 0;
            for (var phase = 0; phase < 5; ++phase)
            {
                while (GetFileAttributesW(result + ".go" + phase) == uint.MaxValue) Sleep(10);

                // Converting a managed callback back to a delegate must retain the original managed object.
                if (!ReferenceEquals(callback, Marshal.GetDelegateForFunctionPointer(callbackPointer,
                    typeof(RawWindowPrint))) || callback(new IntPtr(6)) != 7 ||
                    Marshal.GetFunctionPointerForDelegate(delay) != page ||
                    Marshal.GetFunctionPointerForDelegate(alternate) != page) return 5;
                var workers = new Thread[4];
                var started = 0;
                var armed = 0;
                var armedCalls = 0;
                for (var worker = 0; worker < workers.Length; ++worker)
                {
                    workers[worker] = new Thread(() =>
                    {
                        var informationBytes = IntPtr.Size == 4 ? 28 : 48;
                        var memory = Marshal.AllocHGlobal(informationBytes);
                        try
                        {
                            var iteration = 0;
                            do
                            {
                                long interval = -10000;
                                UIntPtr returned;
                                if ((iteration % 2 == 0 ? delay : alternate)(0, ref interval) != 0 ||
                                    query(new IntPtr(-1), page, 0, memory, new UIntPtr((uint)informationBytes),
                                        out returned) != 0 || returned.ToUInt64() != (uint)informationBytes ||
                                    Marshal.ReadIntPtr(memory) != page)
                                    Interlocked.Exchange(ref status, 6);
                                if (iteration == 0) Interlocked.Increment(ref started);
                                if (iteration == 1) GC.Collect();
                                if (Interlocked.CompareExchange(ref armed, 0, 0) != 0)
                                    Interlocked.Increment(ref armedCalls);
                                ++iteration;
                            } while (phase == 4 ? GetFileAttributesW(result + ".finish") == uint.MaxValue :
                                iteration < 3);
                        }
                        catch (Exception)
                        {
                            Interlocked.Exchange(ref status, 7);
                            Interlocked.Increment(ref started);
                        }
                        finally { Marshal.FreeHGlobal(memory); }
                    });
                    workers[worker].Start();
                }
                if (phase == 4)
                {
                    while (Interlocked.CompareExchange(ref started, 0, 0) < workers.Length) Sleep(1);
                    GC.KeepAlive(Marshal.GetDelegateForFunctionPointer(page, typeof(PrivateDelay)));
                    GC.KeepAlive(Marshal.GetDelegateForFunctionPointer(new IntPtr(page.ToInt64() + 64),
                        typeof(PrivateQuery)));
                    Interlocked.Exchange(ref armed, 1);
                    while (Interlocked.CompareExchange(ref armedCalls, 0, 0) < workers.Length * 2) Sleep(1);
                    File.WriteAllText(result + ".busy", "ready");
                }
                foreach (var worker in workers) worker.Join();
                GC.Collect();
                if (phase == 3)
                {
                    // Reuse the private entry points, then rediscover them while other threads invoke cached delegates.
                    if (!VirtualProtect(page, new UIntPtr(4096), 0x04, out previous)) return 8;
                    offset = 0;
                    foreach (var number in new[] { delayNumber, queryNumber })
                    {
                        var code = PrivateSyscallCode(number, offset == 0 ? 8 : 24);
                        Marshal.Copy(code, 0, new IntPtr(page.ToInt64() + offset), code.Length);
                        offset += 64;
                    }
                    if (!VirtualProtect(page, new UIntPtr(4096), 0x20, out previous)) return 9;
                }
                var output = result + ".phase" + phase;
                File.WriteAllText(output + ".pending", status.ToString(CultureInfo.InvariantCulture) + "|" +
                    (GetModuleHandleW("dynamorio.dll") != IntPtr.Zero));
                File.Move(output + ".pending", output);
            }
            GC.KeepAlive(callback);
            while (GetFileAttributesW(result + ".release") == uint.MaxValue) Sleep(10);
            return status;
        }
        finally { VirtualFree(page, UIntPtr.Zero, 0x8000); }
    }

    private static int ExerciseNativeBoundary(string result)
    {
        // Cache a real CLR native call before capture can replace procedure lookup with an adapter.
        var original = new byte[256];
        var alternate = new byte[256];
        if (!NativeKeyboardProbe(original)) return 1;
        for (var index = 0; index < original.Length; ++index) original[index] = alternate[index] = 0xCD;
        var pinned = GCHandle.Alloc(alternate, GCHandleType.Pinned);
        try
        {
            File.WriteAllText(result + ".ready.pending", pinned.AddrOfPinnedObject().ToInt64().ToString(
                CultureInfo.InvariantCulture));
            File.Move(result + ".ready.pending", result + ".ready");
            while (GetFileAttributesW(result + ".go") == uint.MaxValue) Sleep(20);
            var returned = NativeKeyboardProbe(original);
            var error = Marshal.GetLastWin32Error();
            File.WriteAllText(result + ".complete", (returned ? "1" : "0") + "|" +
                error.ToString(CultureInfo.InvariantCulture) + "|" + Convert.ToBase64String(original) + "|" +
                Convert.ToBase64String(alternate));
            File.Move(result + ".complete", result);
            while (GetFileAttributesW(result + ".release") == uint.MaxValue) Sleep(20);
            return 0;
        }
        finally
        {
            pinned.Free();
        }
    }

    public static int ExecuteNativeBoundary(string result) => ExerciseNativeBoundary(result);
    public static int ExecuteRawNative(string result) => ExerciseRawNative(result);

    public static int Execute(string result) => Main(new[] { result });
    public static int ExecuteAttach(string result) => Main(new[] { result, "--attach" });
    public static int ExecuteAttachSmoke(string result) => Main(new[] { result, "--attach-smoke" });
    public static int ExecuteLayouts(string result) => Main(new[] { result, "--layouts" });
    public static int ExecuteLayoutLifecycle(string result) => Main(new[] { result, "--layouts-lifecycle" });
    public static int ExecuteArrays(string result) => Main(new[] { result, "--arrays" });
    public static int ExecuteArraysDebugger(string result) => Main(new[] { result, "--arrays-debugger" });
    public static int ExecuteArraysDebuggerCopy(string result) => Main(new[] { result, "--arrays-debugger-copy" });
    public static int ExecuteArraysDebuggerGeneric(string result) =>
        Main(new[] { result, "--arrays-debugger-generic" });

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string ExerciseArray<T>(T first, T second) where T : struct
    {
        // The IL sizeof result verifies array padding independently of profiler metadata and marshaling rules.
        var size = new DynamicMethod("ArrayElementSize", typeof(int), Type.EmptyTypes, typeof(ManagedTarget));
        var il = size.GetILGenerator();
        il.Emit(OpCodes.Sizeof, typeof(T));
        il.Emit(OpCodes.Ret);
        var stride = ((ArrayElementSize)size.CreateDelegate(typeof(ArrayElementSize)))();
        var list = new List<T>(new[] { first, second, first });
        if (!EqualityComparer<T>.Default.Equals(list[0], first)) Interlocked.Increment(ref failures);
        var returned = list.ToArray();
        var empty = new List<T>().ToArray();
        var destination = new T[3];
        list.CopyTo(destination, 0);
        Array.Resize(ref destination, 4);
        T[] missing = null;
        Array.Resize(ref missing, 2);
        Array.Resize(ref missing, 0);
        if (returned.Length != 3 || destination.Length != 4 ||
            empty.Length != 0 || missing.Length != 0 ||
            !EqualityComparer<T>.Default.Equals(returned[1], second) ||
            !EqualityComparer<T>.Default.Equals(destination[1], second)) Interlocked.Increment(ref failures);
        return typeof(T).Name + "=" + stride.ToString(CultureInfo.InvariantCulture);
    }

#if NET10_0
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ExerciseRuntimeArrays()
    {
        // The compatibility facade forwards Array to the runtime's defining core library.
        if (Assembly.Load("mscorlib").GetType("System.Array") != typeof(Array)) ++failures;

        // Runtime-sized snapshots include empty, singleton, ranked and reference-containing arrays.
        Array.Copy(new long[0], new long[0], 0);
        Array.Copy(Array.CreateInstance(typeof(int), new[] { 0, 2 }, new[] { -1, 3 }),
            Array.CreateInstance(typeof(int), new[] { 0, 2 }, new[] { -1, 3 }), 0);
        var singleton = new[] { new ManagedArrayPacked { Number = 0x11223344, Tag = 0x5A } };
        var copied = new ManagedArrayPacked[1];
        Array.Copy(singleton, copied, 1);
        if (copied[0].Number != 0x11223344 || copied[0].Tag != 0x5A) ++failures;
        var ordered = new int[3];
        ((System.Collections.ICollection)new SortedSet<int> { 0x11223344, 0x55667788 }).CopyTo(ordered, 1);
        if (ordered[0] != 0 || ordered[1] != 0x11223344 || ordered[2] != 0x55667788) ++failures;
        var references = new object[] { new byte[11], null };
        var referenceCopy = new object[2];
        Array.Copy(references, referenceCopy, 2);
        if (!ReferenceEquals(references[0], referenceCopy[0]) || referenceCopy[1] != null) ++failures;
        var ranked = Array.CreateInstance(typeof(string), new[] { 1, 1 }, new[] { -2, 3 });
        var rankedCopy = Array.CreateInstance(typeof(string), new[] { 1, 1 }, new[] { -2, 3 });
        ranked.SetValue("ranked-reference", -2, 3);
        Array.Copy(ranked, rankedCopy, 1);
        if ((string)rankedCopy.GetValue(-2, 3) != "ranked-reference") ++failures;

        // Application calls to capture helpers remain observable, including their exceptional exits.
        try { Marshal.UnsafeAddrOfPinnedArrayElement((Array)null, 0); ++failures; }
        catch (ArgumentNullException) { }
        var pin = GCHandle.Alloc(singleton, GCHandleType.Pinned);
        try
        {
            if (Marshal.UnsafeAddrOfPinnedArrayElement((Array)singleton, 0) != pin.AddrOfPinnedObject() ||
                ((Array)singleton).LongLength != 1) ++failures;
        }
        finally { pin.Free(); }
        try { Array.Copy(null, new long[0], 0); ++failures; }
        catch (ArgumentNullException) { }

        // Repeated snapshots must keep references valid while another thread compacts the heap.
        var values = new[]
        {
            new ManagedArrayReference { Reference = new byte[13], Number = 0x1122334455667788 },
            new ManagedArrayReference { Number = 0x7766554433221100 }
        };
        var output = new ManagedArrayReference[2];
        var active = 1;
        using var started = new ManualResetEvent(false);
        var worker = new Thread(() =>
        {
            started.Set();
            while (Volatile.Read(ref active) != 0)
            {
                GC.Collect(2, GCCollectionMode.Forced, true, true);
                Thread.Sleep(1);
            }
        });
        worker.Start();
        started.WaitOne();
        try
        {
            for (var index = 0; index < 32; ++index)
            {
                Array.Copy(values, output, 2);
                if (!ReferenceEquals(values[0].Reference, output[0].Reference) || output[1].Reference != null ||
                    output[0].Number != values[0].Number || output[1].Number != values[1].Number) ++failures;
                Thread.Sleep(1);
            }
        }
        finally { Volatile.Write(ref active, 0); worker.Join(); }
    }
#endif

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ExerciseLayouts(string lifecycle, bool dynamicAssemblies = true)
    {
        // Loaded value types exercise nested fields, closed generic fields, by-value arguments and returns.
        var identity = new Guid("00112233-4455-6677-8899-aabbccddeeff");
        var timestamp = new DateTime(2020, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        var offset = new DateTimeOffset(timestamp);
        if (offset.AddMinutes(3).UtcDateTime != timestamp.AddMinutes(3)) Interlocked.Increment(ref failures);
        var pair = new KeyValuePair<int, Guid>(0x12345678, identity);
        if (pair.Key != 0x12345678 || pair.Value != identity ||
            !EqualityComparer<KeyValuePair<int, Guid>>.Default.Equals(pair, pair)) Interlocked.Increment(ref failures);
        var nested = new KeyValuePair<int, KeyValuePair<Guid, long>>(17,
            new KeyValuePair<Guid, long>(identity, 0x1122334455667788));
        if (nested.Value.Key != identity || nested.Value.Value != 0x1122334455667788)
            Interlocked.Increment(ref failures);
        var reference = new KeyValuePair<int, int[]>(23, new[] { 1, 2, 3 });
        var text = new KeyValuePair<int, string>(29, "layout");
        if (reference.Value.Length != 3 || text.Value != "layout") Interlocked.Increment(ref failures);
        var duration = TimeSpan.FromSeconds(123.25);
        if (decimal.Add(123.5m, 6.25m) != 129.75m || duration.Ticks != 1232500000 ||
            duration.Add(new TimeSpan(10000000)).Ticks != 1242500000)
            Interlocked.Increment(ref failures);
        if (XmlConvert.ToDateTimeOffset("2020-05-06T07:08:09Z") != offset ||
            XmlConvert.ToDateTimeOffset(XmlConvert.ToString(offset)) != offset ||
            XmlConvert.ToTimeSpan("PT123.25S") != duration) Interlocked.Increment(ref failures);
        var forwarded = new KeyValuePair<int, ManagedLayoutValue>(31, new ManagedLayoutValue { Timestamp = offset });
        if (forwarded.Value.Timestamp != offset) Interlocked.Increment(ref failures);
        if (dynamicAssemblies) ExerciseAssemblyLayouts(lifecycle);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ExerciseAssemblyLayouts(string lifecycle)
    {
        // Equal type names in distinct assembly versions must retain their different field widths.
        static ModuleBuilder Module(string name, int version)
        {
            var identity = new AssemblyName(name) { Version = new Version(version, 0, 0, 0) };
#if NET10_0
            var assembly = AssemblyBuilder.DefineDynamicAssembly(identity, AssemblyBuilderAccess.Run);
#else
            var assembly = AppDomain.CurrentDomain.DefineDynamicAssembly(identity, AssemblyBuilderAccess.Run);
#endif
            return assembly.DefineDynamicModule(name + ".dll");
        }
        var consumer = Module("Detourist.LayoutConsumers", 1);
        var sources = new Type[2];
        var wrappers = new Type[2];
        var values = new object[2];
        var attributes = TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout;
        for (var index = 0; index < 2; ++index)
        {
            var source = Module("Detourist.LayoutSource", index + 1)
                .DefineType("LayoutShared.Value", attributes, typeof(ValueType));
            source.DefineField("Number", index == 0 ? typeof(int) : typeof(long), FieldAttributes.Public);
            sources[index] = source.CreateType();
            var wrapper = consumer.DefineType("LayoutTest.Wrapper" + (index == 0 ? "32" : "64"),
                attributes, typeof(ValueType));
            wrapper.DefineField("Inner", sources[index], FieldAttributes.Public);
            wrappers[index] = wrapper.CreateType();
        }
        for (var index = 0; index < 2; ++index)
        {
            object expected = index == 0 ? (object)0x12345678 : 0x1122334455667788L;
            var source = Activator.CreateInstance(sources[index]);
            sources[index].GetField("Number").SetValue(source, expected);
            var wrapper = Activator.CreateInstance(wrappers[index]);
            wrappers[index].GetField("Inner").SetValue(wrapper, source);
            values[index] = wrapper;
            var type = typeof(KeyValuePair<,>).MakeGenericType(typeof(int), wrappers[index]);
            var pair = Activator.CreateInstance(type, new object[] { 37 + index, wrapper });
            var returned = type.GetProperty("Value").GetValue(pair, null);
            var inner = wrappers[index].GetField("Inner").GetValue(returned);
            if (!expected.Equals(sources[index].GetField("Number").GetValue(inner)))
                Interlocked.Increment(ref failures);
        }
        var mixedType = typeof(KeyValuePair<,>).MakeGenericType(wrappers);
        var mixed = Activator.CreateInstance(mixedType, values);
        var mixedValue = mixedType.GetProperty("Value").GetValue(mixed, null);
        var mixedInner = wrappers[1].GetField("Inner").GetValue(mixedValue);
        if (!0x1122334455667788L.Equals(sources[1].GetField("Number").GetValue(mixedInner)))
            Interlocked.Increment(ref failures);

        // Large layouts cross metadata record boundaries while value bytes remain independently bounded.
        var large = consumer.DefineType("LayoutTest.LargeValue", attributes, typeof(ValueType));
        for (var index = 0; index < 200; ++index)
            large.DefineField("RetainedValueFieldForCapture_" + index.ToString("D3") + "_Ω",
                typeof(long), FieldAttributes.Public);
        var largeType = large.CreateType();
        var largeValue = Activator.CreateInstance(largeType);
        for (var index = 0; index < 200; ++index)
            largeType.GetField("RetainedValueFieldForCapture_" + index.ToString("D3") + "_Ω")
                .SetValue(largeValue, 1000L + index);
        var largePairType = typeof(KeyValuePair<,>).MakeGenericType(typeof(int), largeType);
        var largePair = Activator.CreateInstance(largePairType, new object[] { 43, largeValue });
        var largeResult = largePairType.GetProperty("Value").GetValue(largePair, null);
        if (!1199L.Equals(largeType.GetField("RetainedValueFieldForCapture_199_Ω").GetValue(largeResult)))
            Interlocked.Increment(ref failures);
        if (lifecycle == null) return;

        // Reuse the same loaded method and value after the collector detaches and starts a new session.
        File.WriteAllText(lifecycle + ".ready", "ready");
        while (GetFileAttributesW(lifecycle + ".go") == uint.MaxValue) Sleep(20);
        largeResult = largePairType.GetProperty("Value").GetValue(largePair, null);
        if (!1199L.Equals(largeType.GetField("RetainedValueFieldForCapture_199_Ω").GetValue(largeResult)))
            Interlocked.Increment(ref failures);
        File.WriteAllText(lifecycle + ".done", "done");
        while (GetFileAttributesW(lifecycle + ".release") == uint.MaxValue) Sleep(20);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ExerciseFramework()
    {
        // Win32u forwarders must remain typed when a CLR interop thunk enters the window-system API.
        var keys = new byte[256];
        if (!GetKeyboardState(keys) || !NtUserGetKeyboardState(keys)) Interlocked.Increment(ref failures);
        var nativeTime = (NativeTime)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(GetModuleHandleW("ntdll.dll"), "ZwQuerySystemTime"), typeof(NativeTime));

        // Value-type receivers retain their actual unboxed data across supported CLR generations.
        var identity = new Guid("00112233-4455-6677-8899-aabbccddeeff");
        if (identity.ToByteArray().Length != 16) Interlocked.Increment(ref failures);

        // Actual framework calls exercise scalar, string, array, exception, and generic method observations.
        for (var iteration = 0; iteration < repetitions; ++iteration)
        {
            var prefix = new string('d', 96);
            var text = string.Concat(prefix, "etourist");
            if (text.Length != 104 || !text.EndsWith("etourist", StringComparison.Ordinal))
                Interlocked.Increment(ref failures);
            if (int.Parse("123456", CultureInfo.InvariantCulture) != 123456)
                Interlocked.Increment(ref failures);
            if (!int.TryParse("654321", out var parsed) || parsed != 654321)
                Interlocked.Increment(ref failures);
            var resized = new byte[128];
            for (var index = 0; index < resized.Length; ++index) resized[index] = 0x37;
            Array.Resize(ref resized, 512);
            if (resized.Length != 512 || resized[0] != 0x37 || resized[511] != 0)
                Interlocked.Increment(ref failures);
            var bytes = System.Text.Encoding.UTF8.GetBytes(text);
            if (bytes.Length != text.Length) Interlocked.Increment(ref failures);
            using (var reader = new BufferedStream(new GcReadStream(), 64))
            {
                var output = new byte[256];
                for (var index = 0; index < output.Length; ++index) output[index] = 0xA5;
                if (reader.Read(output, 0, 96) != 96) Interlocked.Increment(ref failures);
                for (var index = 0; index < output.Length; ++index)
                    if (output[index] != (index < 96 ? 0x6B : 0xA5)) Interlocked.Increment(ref failures);
            }
            var list = new List<string>();
            list.Add(text);
            if (list.Count != 1 || list[0] != text) Interlocked.Increment(ref failures);
            try
            {
                int.Parse("not-an-integer", CultureInfo.InvariantCulture);
                Interlocked.Increment(ref failures);
            }
            catch (FormatException)
            {
            }
            if (Math.Abs(Math.Sin(0.5) - 0.479425538604203) > 1e-14)
                Interlocked.Increment(ref failures);
#if NET10_0
            var vector = Vector256.Create(1.25 + iteration, 2.5, 3.75, 5.0);
            vector = Vector256.Add(vector, Vector256.Create(2.0));
            var scalar = double.Parse("7.0", CultureInfo.InvariantCulture);
            if (vector.GetElement(0) != 3.25 + iteration || vector.GetElement(3) != scalar)
                Interlocked.Increment(ref failures);
#endif
            GC.Collect();
            if (NtQuerySystemTime(out var systemTime) != 0 || systemTime < 132000000000000000)
                Interlocked.Increment(ref failures);
            if (nativeTime(out systemTime) != 0 || systemTime < 132000000000000000)
                Interlocked.Increment(ref failures);
            if (!WinHttpTimeToSystemTime("Wed, 21 Oct 2015 07:28:00 GMT", out var time) ||
                time.Year != 2015 || time.Month != 10 || time.Day != 21 || time.Hour != 7 || time.Minute != 28)
                Interlocked.Increment(ref failures);
        }
    }
}
