using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static async Task CatalogEditing()
    {
        // Every edit runs against a private copy of the shipped catalog in a folder whose name needs quoting.
        var root = Path.Combine(Path.GetTempPath(), "Detourist Catalog Editor " + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "ApiCatalog.sqlite");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "ApiCatalog.sqlite"), path);
        try
        {
            // A native library beside an opened file must not enter the application's DLL search path.
            const string probe = "DetouristSearchProbe.dll";
            File.Copy(Path.Combine(AppContext.BaseDirectory, "DetouristSqlite.dll"), Path.Combine(root, probe));
            var directory = Environment.CurrentDirectory;
            try
            {
                Environment.CurrentDirectory = root;
                var loaded = NativeLibrary.TryLoad(probe, typeof(CatalogStore).Assembly, null, out var library);
                if (library != 0) NativeLibrary.Free(library);
                Require(!loaded, "A native library was loaded from the current directory.");
            }
            finally { Environment.CurrentDirectory = directory; }

            CatalogArchitectures(path);
            await CatalogStoreRules(path);
            await CatalogOptimization(path);
            await CatalogEditorWindowFlow(path);
            await CatalogReadOnly(root, path);
        }
        finally
        {
            foreach (var file in Directory.GetFiles(root)) File.SetAttributes(file, FileAttributes.Normal);
            Directory.Delete(root, true);
        }
    }

    private static void CatalogArchitectures(string path)
    {
        using var metadata64 = new CatalogDatabase(path);
        using var metadata32 = new CatalogDatabase(path, 4);
        using var editor64 = new CatalogStore(path);
        using var editor32 = new CatalogStore(path, 4);
        Require(metadata64.Type("SIZE_T")?.Size == 8 && metadata32.Type("SIZE_T")?.Size == 4 &&
            metadata64.Type("AM_MEDIA_TYPE")?.Size == 88 && metadata32.Type("AM_MEDIA_TYPE")?.Size == 72,
            "The catalog did not select the stored target layouts.");

        // A saved layout invalidates cached misses without changing the other architecture's data.
        const string name = "DETOURIST_ARCHITECTURE_FIXTURE";
        const string layout = """{"kind":"Integer","size":4}""";
        Require(metadata64.Type(name) is null && metadata32.Type(name) is null, "Unexpected fixture layout.");
        editor32.SaveType(name, null, layout);
        metadata32.Refresh();
        metadata64.Refresh();
        Require(metadata32.Type(name)?.Size == 4 && metadata64.Type(name) is null,
            "An x86 layout edit changed x64 metadata or retained a cached miss.");
        var previous64 = Environment.GetEnvironmentVariable("DETOURIST_API_CATALOG");
        var previous32 = Environment.GetEnvironmentVariable("DETOURIST_API_CATALOG_X86");
        try
        {
            // The inspector and collector select the same catalog when only the x64 path is overridden.
            Environment.SetEnvironmentVariable("DETOURIST_API_CATALOG", path);
            Environment.SetEnvironmentVariable("DETOURIST_API_CATALOG_X86", null);
            using var installed = new CatalogDatabase(pointerSize: 4);
            Environment.SetEnvironmentVariable("DETOURIST_API_CATALOG_X86", path);
            using var custom = new CatalogDatabase(pointerSize: 4);
            Require(installed.Type(name) is null && custom.Type(name)?.Size == 4,
                "The x86 inspector opened the wrong catalog.");
        }
        finally
        {
            Environment.SetEnvironmentVariable("DETOURIST_API_CATALOG", previous64);
            Environment.SetEnvironmentVariable("DETOURIST_API_CATALOG_X86", previous32);
        }
        editor32.SaveType(name, layout, null);

        using (ApiMetadata.UsePointerSize(4))
        {
            Require(ParameterType.Infer("__ptr64 void *").Bits == 64 && ParameterType.Infer("void *").Bits == 32,
                "The x86 inspector lost an explicitly wide pointer.");
            Require(ApiMetadata.Type("vulkan::VkPhysicalDeviceFeatures2")?.Size > 0,
                "The inspector lost the recorded width of an external SDK type.");
        }

        // Function declarations and their rule sources belong to the selected architecture as well.
        var function = Tick(editor32);
        var original64 = editor64.State(function.Id);
        var edited = function.State with { Summary = "Architecture fixture" };
        editor32.Save(function.Id, function.State, edited);
        Require(editor32.State(function.Id) == edited && editor64.State(function.Id) == original64,
            "An x86 declaration edit changed x64 metadata.");
        editor32.Save(function.Id, edited, function.State);
    }

    private static async Task CatalogStoreRules(string path)
    {
        using var store = new CatalogStore(path);
        using var other = new CatalogStore(path);
        Require(await CatalogValidator.Check("") is not null, "An empty catalog path validated the installed catalog.");
        Require(!store.ReadOnly && store.Tables().Contains("capture_parameters"), "The catalog tables are not listed.");
        Require(store.Browse("capture_parameters", "", 10).Rows.Count == 10, "A catalog view could not be browsed.");

        // Alias searches and inspector lookups retain exact-module overrides.
        using (var metadata = new CatalogDatabase(path))
        {
            var found = store.Functions("libcrypto-3-x64.dll!CRYPTO_memcmp", 10);
            Require(found.Any(item => item.Module == "libcrypto-3.dll" && item.Name == "CRYPTO_memcmp"),
                "An exact alias did not find the shared catalog entry.");
            var aliasSignature = metadata.Function("CRYPTO_memcmp", "libcrypto-3-x64.dll");
            Require(aliasSignature?.Parameters is [{ Name: "in_a" }, { Name: "in_b" }, { Name: "len" }] &&
                metadata.Function("CRYPTO_memcmp", "LIBCRYPTO-3-X64.DLL")?.Parameters.Length == 3 &&
                metadata.Function("CRYPTO_memcmp", "libcrypto-30.dll") is null,
                "An alias resolved the wrong module or declaration.");
            Raw(path, "INSERT INTO functions(module,name,result,signature,summary,variant) " +
                "SELECT 'libcrypto-3-x64.dll',name,result,replace(signature,'in_a','specific'),summary,variant " +
                "FROM functions WHERE module='libcrypto-3.dll' AND name='CRYPTO_memcmp'");
            Require(metadata.Refresh() && metadata.Function("CRYPTO_memcmp", "libcrypto-3-x64.dll")?.
                Parameters[0].Name == "specific", "An exact declaration did not override the module alias.");
            Raw(path, "DELETE FROM functions WHERE module='libcrypto-3-x64.dll' AND name='CRYPTO_memcmp'");
            Require(metadata.Refresh() && metadata.Function("CRYPTO_memcmp", "libcrypto-3-x64.dll")?.
                Parameters[0].Name == "in_a", "An alias did not resume after its override was removed.");
        }

        // A source declaration propagates to the aliases that follow it, and a redundant summary is not stored.
        static CatalogFunction Exact(CatalogStore store, string qualified) => store.Functions(qualified, 50)
            .Single(item => item.Variant.Length == 0 && $"{item.Module}!{item.Name}" == qualified);
        var alias = Exact(store, "api-ms-win-core-stringloader-l1-1-0.dll!LoadStringW");
        Require(alias.AliasSource is not null, "The fixture alias does not name its source.");
        var source = Exact(store, alias.AliasSource!);
        var renamed = string.Join('\n', source.State.Signature.Split('\n')
            .Select((line, index) => line.Replace('\t', ' ') + (index == 0 ? "Renamed" : "")));
        var (desired, problem) = CatalogStore.Desired(source, source.State.Result, renamed,
            renamed.Replace("\n", ", "), source.State.Rule, source.State.Source ?? "");
        Require(desired is not null && desired.Summary is null,
            problem ?? "A summary equal to the parameters was stored.");
        store.Save(source.Id, source.State, desired!);
        Require(store.Function(alias.Id)!.State.Signature == desired!.Signature,
            "An alias did not follow its source's new declaration.");

        // A row changed by another writer since it was loaded is never overwritten.
        var stale = store.Function(source.Id)!;
        other.Save(stale.Id, stale.State, stale.State with { Summary = "Changed by another tool" });
        try
        {
            store.Save(stale.Id, stale.State, stale.State with { Result = "UINT" });
            throw new InvalidOperationException("A stale declaration overwrote a concurrent change.");
        }
        catch (CatalogConflictException)
        {
        }
        Require(store.Function(stale.Id)!.State is { Summary: "Changed by another tool", Result: var kept } &&
            kept == stale.State.Result, "The concurrent change was lost.");

        // Declarations keep the plan's argument count, and results the plan does not capture get no failure rule.
        (_, problem) = CatalogStore.Desired(source, source.State.Result, "HINSTANCE hInstance", "",
            source.State.Rule, "");
        Require(problem?.Contains("capture plan passes") == true, "A declaration disagreed with its capture plan.");
        var silent = store.Functions("glAccum", 5).First(item => item.ResultBytes == 0);
        (_, problem) = CatalogStore.Desired(silent, silent.State.Result,
            string.Join('\n', silent.State.Signature.Split('\n').Select(line => line.Replace('\t', ' '))), "", 2,
            "documentation");
        Require(problem?.Contains("no result") == true, "A failure rule was accepted for a result the plan ignores.");

        // A layout the name already implies is not stored, and invalid layouts never reach the catalog.
        Require(CatalogStore.ValidateLayout("WIDGET", "{\"kind\":\"Structure\"").Error is not null,
            "Malformed layout JSON was accepted.");
        Require(CatalogStore.ValidateLayout("WIDGET", """{"kind":"Structure","size":4,"fields":[{"name":"Value",""" +
            """ "type":"DWORD","offset":32}]}""").Error is not null, "A field outside its structure was accepted.");
        var (pointer, _) = CatalogStore.ValidateLayout("WIDGET *",
            """{"kind":"Pointer","size":8,"element":"WIDGET"}""");
        store.SaveType("WIDGET *", null, """{"kind":"Pointer","size":16,"element":"WIDGET"}""");
        store.SaveType("WIDGET *", store.Layout("WIDGET *"), pointer);
        Require(store.Layout("WIDGET *") is null, "A derivable pointer layout was stored.");
        Require(await CatalogValidator.Check(path) is null, "The capture engine rejected the edited catalog.");

        // Alias chains are rejected before a malformed catalog reaches either capture engine.
        Raw(path, "UPDATE module_aliases SET module='libcrypto-1_1-x64.dll' WHERE alias='libcrypto-3-x64.dll'");
        try
        {
            Require((await CatalogValidator.Check(path))?.Contains("module alias chain") == true,
                "The capture engine accepted an alias chain.");
        }
        finally
        {
            Raw(path, "UPDATE module_aliases SET module='libcrypto-3.dll' WHERE alias='libcrypto-3-x64.dll'");
        }
    }

    private static async Task CatalogOptimization(string path)
    {
        // Deleted payloads leave free pages, and missing statistics must be rebuilt without changing catalog rows.
        Raw(path, "CREATE TABLE optimize_space(value BLOB)");
        Raw(path, "INSERT INTO optimize_space VALUES(zeroblob(8388608))");
        Raw(path, "DROP TABLE optimize_space");
        Raw(path, "DROP TABLE sqlite_stat1");
        using var store = new CatalogStore(path);
        var before = Tick(store);
        var layout = store.Layout("POINT");
        var size = new FileInfo(path).Length;
        Require(store.Browse("pragma_freelist_count", "", 1).Rows[0][0].ToString() != "0",
            "The optimization fixture has no reclaimable pages.");
        await Task.Run(() => store.Optimize());
        Require(new FileInfo(path).Length < size &&
            store.Browse("pragma_freelist_count", "", 1).Rows[0][0].ToString() == "0",
            "Optimization did not reclaim unused database pages.");
        Require(store.Browse("sqlite_stat1", "", 1).Rows.Count == 1,
            "Optimization did not create query statistics.");
        Require(Tick(store) is var after && after.Id == before.Id && after.State == before.State &&
            store.Layout("POINT") == layout, "Optimization changed a catalog declaration or layout.");
        Require(await CatalogValidator.Check(path) is null, "The capture engine rejected the optimized catalog.");

        // A reader holding an old WAL snapshot prevents truncation; retrying after it closes reclaims the log.
        Raw(store, "PRAGMA journal_mode=WAL");
        Raw(store, "PRAGMA busy_timeout=50");
        using var reader = new CatalogStore(path);
        Raw(reader, "BEGIN");
        _ = Tick(reader);
        try
        {
            await Task.Run(() => store.Optimize());
            throw new InvalidOperationException("A blocked checkpoint was reported as complete.");
        }
        catch (IOException error) when (error.Message.Contains("write-ahead log is still in use"))
        {
        }
        finally
        {
            Raw(reader, "ROLLBACK");
        }
        await Task.Run(() => store.Optimize());
        Require(new FileInfo(path + "-wal").Length == 0 && Tick(reader).State == before.State,
            "Optimization did not truncate the WAL or preserve the reader's catalog data.");
    }

    private static async Task CatalogEditorWindowFlow(string path)
    {
        // Saves made through the window are checked by the engine and undone when another tool broke the catalog.
        var window = new CatalogEditorWindow(path) { WindowState = WindowState.Minimized, ShowActivated = false };
        window.Show();
        try
        {
            T Control<T>(string name) where T : FrameworkElement =>
                Elements(window).OfType<T>().Single(item => AutomationProperties.GetName(item) == name);
            var status = Elements(window).OfType<TextBlock>().ToArray();
            await Until(() => status.Any(text => text.Text.StartsWith("The capture engine accepts")),
                "The editor did not check the catalog with the capture engine.");
            // Architecture selection reloads the stored layouts before the user starts editing.
            var architecture = Control<ComboBox>("Architecture");
            var selectedTabs = Elements(window).OfType<TabControl>().Single();
            selectedTabs.SelectedIndex = 1;
            var typeSearch = Control<TextBox>("Search types by name");
            typeSearch.Text = "SIZE_T";
            architecture.SelectedIndex = 1;
            await Until(() => Elements(window).OfType<DataGrid>().SelectMany(grid => grid.Items.OfType<CatalogType>())
                .Any(item => item.Name == "SIZE_T" && item.Size == 4), "The editor did not select x86 layouts.");
            await Program.SaveView(window, "catalog-types-x86");
            architecture.SelectedIndex = 0;
            await Until(() => Elements(window).OfType<DataGrid>().SelectMany(grid => grid.Items.OfType<CatalogType>())
                .Any(item => item.Name == "SIZE_T" && item.Size == 8), "The editor did not restore x64 layouts.");
            selectedTabs.SelectedIndex = 0;
            await Until(() => status.Any(text => text.Text.StartsWith("The capture engine accepts")),
                "The editor did not recheck the selected architecture.");
            var search = Control<TextBox>("Search functions by name, or module!name");
            var grid = Elements(window).OfType<DataGrid>().First();
            search.Text = "libcrypto-3.dll!RAND_bytes";
            await Until(() => grid.Items.OfType<CatalogFunction>().Any(item => item.Name == "RAND_bytes" &&
                item.Module == "libcrypto-3.dll"), "The function search did not find RAND_bytes.");
            grid.SelectedItem = grid.Items.OfType<CatalogFunction>().First(item => item.Name == "RAND_bytes" &&
                item.Module == "libcrypto-3.dll");
            Require(Control<ComboBox>("Failure rule").SelectedIndex == 5 && !Control<Button>("Save function").IsEnabled,
                "Selecting a nonpositive failure rule changed the stored convention.");
            search.Text = "kernel32.dll!GetTickCount64";
            await Until(() => grid.Items.OfType<CatalogFunction>().Any(item => item.Name == "GetTickCount64" &&
                item.Module == "kernel32.dll"), "The function search did not find its match.");
            grid.SelectedItem = grid.Items.OfType<CatalogFunction>().First(item => item.Name == "GetTickCount64" &&
                item.Module == "kernel32.dll");
            var summary = Control<TextBox>("Summary");
            Require(summary.IsEnabled, "The selected function's declaration is not editable.");
            await Program.SaveView(window, "catalog-functions");
            (window.Width, window.Height) = (window.MinWidth, window.MinHeight);
            await Program.SaveView(window, "catalog-functions-compact");
            var fontSize = window.FontSize;
            window.FontSize *= 1.25;
            await Program.SaveView(window, "catalog-functions-scaled");
            window.FontSize = fontSize;
            (window.Width, window.Height) = (1240, 780);
            summary.Text = "Milliseconds since the system started";
            var save = Control<Button>("Save function");
            Require(save.IsEnabled, "An edited declaration cannot be saved.");

            // Maintenance returns to the dispatcher, pauses pending searches and keeps unsaved edits in place.
            var optimize = Control<Button>("Optimize catalog");
            Require(optimize.IsVisible, "A writable catalog has no optimization action.");
            search.Text += " ";
            optimize.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
            Require(!window.IsEnabled, "Optimization did not enter its busy state.");
            window.Close();
            Require(window.IsLoaded, "The editor closed while maintenance owned its database connection.");
            await Until(() => window.IsEnabled && status.Any(text => text.Text.StartsWith("Catalog optimized.")),
                "Catalog optimization did not finish successfully.");
            Require(summary.Text == "Milliseconds since the system started" && save.IsEnabled,
                "Optimization discarded or saved an unsaved declaration.");
            using (var check = new CatalogStore(path))
                Require(Tick(check).State.Summary is null, "Optimization saved an unsaved declaration.");

            const string broken = "UPDATE capture_rules SET kind=kind+100 WHERE id=" +
                "(SELECT min(id) FROM capture_rules WHERE kind=0)";
            Raw(path, broken);
            save.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
            await Until(() => window.IsEnabled && status.Any(text => text.Text.Contains("rejected the change")),
                "A save the capture engine rejects was not reported.");
            using (var other = new CatalogStore(path))
                Require(Tick(other).State.Summary is null,
                    "A save the capture engine rejected remained in the catalog.");
            Raw(path, "UPDATE capture_rules SET kind=kind-100 WHERE kind>=100");
            summary.Text = "Milliseconds since the system started";
            save.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
            await Until(() => window.IsEnabled && status.Any(text => text.Text.StartsWith("Saved GetTickCount64")),
                "A valid save was not confirmed.");
            using (var check = new CatalogStore(path))
                Require(Tick(check).State.Summary ==
                    "Milliseconds since the system started", "The saved summary is not in the catalog.");
            var tabs = Elements(window).OfType<TabControl>().Single();
            foreach (var (index, name) in new[] { (1, "catalog-types"), (2, "catalog-tables") })
            {
                tabs.SelectedIndex = index;
                await Task.Delay(400);
                await Program.SaveView(window, name);
            }
        }
        finally
        {
            window.Close();
        }
    }

    private static async Task CatalogReadOnly(string root, string path)
    {
        // A catalog the user cannot write still opens for browsing, and saving reports why it cannot change.
        var copy = Path.Combine(root, "ReadOnly.sqlite");
        File.Copy(path, copy);
        File.SetAttributes(copy, FileAttributes.ReadOnly);
        using var store = new CatalogStore(copy);
        var function = Tick(store);
        Require(store.ReadOnly, "A read-only catalog opened for writing.");
        try
        {
            store.Save(function.Id, function.State, function.State with { Summary = "Not saved" });
            throw new InvalidOperationException("A read-only catalog accepted a save.");
        }
        catch (IOException error) when (error.Message.Contains("read-only"))
        {
        }
        try
        {
            store.Optimize();
            throw new InvalidOperationException("A read-only catalog accepted optimization.");
        }
        catch (IOException error) when (error.Message.Contains("read-only"))
        {
        }
        var window = new CatalogEditorWindow(copy) { WindowState = WindowState.Minimized, ShowActivated = false };
        window.Show();
        try
        {
            Require(Elements(window).OfType<Button>().Single(button =>
                AutomationProperties.GetName(button) == "Optimize catalog").Visibility == Visibility.Collapsed,
                "A read-only catalog offers optimization.");
            await Until(() => Elements(window).OfType<TextBlock>().Any(text =>
                text.Text.StartsWith("The capture engine accepts")), "The read-only catalog did not finish loading.");
        }
        finally
        {
            window.Close();
        }
    }

    private static CatalogFunction Tick(CatalogStore store) => store.Functions("kernel32.dll!GetTickCount64", 50)
        .Single(item => item.Module == "kernel32.dll" && item.Name == "GetTickCount64");

    private static async Task Until(Func<bool> condition, string message, int seconds = 60)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition())
        {
            Require(deadline.Elapsed < TimeSpan.FromSeconds(seconds), message);
            await Task.Delay(50);
        }
    }

    // Another tool writes the catalog directly, outside the editor's validated operations.
    private static void Raw(string path, string sql)
    {
        using var writer = new CatalogStore(path);
        Raw(writer, sql);
    }

    private static void Raw(CatalogStore writer, string sql)
    {
        typeof(CatalogStore).GetMethod("Execute", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(writer, [sql, Array.Empty<object?>()]);
    }
}
