# Detourist

Detourist shows which Windows API calls an application makes, what each call returns, and how long it takes. Use a trace to see which file an application tried to open, find a slow call, or identify the code that made a call.

## Install Detourist

Detourist runs on 64-bit Windows and can trace both 32-bit (x86) and 64-bit (x64) applications. Choose a package from the [latest release](https://github.com/NoMoreFood/Detourist/releases/latest).

- **MSI installer** — Run the `.msi` and open **Detourist** from the Start menu.
- **Portable ZIP** — Extract the entire ZIP to a folder and run `Detourist.exe` there. Keep the `x86` subfolder and the other extracted files together.

To compile Detourist yourself, see the [source build guide](Build/README.md).

## Record a trace

For a file or network problem, you can narrow the recording before you start. Choose **File / registry / network I/O** from **Capture mode**.

1. Choose **Launch** to record an application from startup. Select its `.exe` and enter any command-line arguments it needs. For an application that is already running, choose **Attach** and select the process by name or ID.
2. Perform the action you want to examine in the application, such as opening a document. The calls appear in Detourist as the application runs.
3. Select **Stop** when the action finishes. The trace stays open for inspection.

Detourist saves each recording automatically as a SQLite `.db` file in `%LOCALAPPDATA%\Detourist\Traces`, named after the application and start time. Use **Open trace** (`Ctrl+O`) or drag a saved trace into the window to reopen it. To save future traces elsewhere, change **Trace folder** under **Settings** → **General**.

## Inspect a trace

- **Investigate a failure.** Select **Failures**, then select a call. For a failed file operation, check the path in **Parameters** and the return value in the **Result** column. The **Call stack** tab shows the callers when stacks were recorded.
- **Find a delay.** Choose **Slowest first** to see which individual calls took the longest. Select **Summary** to compare call counts, failures, and time by API. Double-click a summary row to see its calls.
- **Navigate a busy trace.** Filter by process, thread, or category. Click the timeline to jump to calls near a particular time, or use **Find** (`Ctrl+F`) and `F3` to step through matches.

If an expected call is missing, clear any display filters with **Reset filters**. Open **Coverage** to check what Detourist could monitor for that process. To choose which categories or sources to record next time, use **Settings** → **Capture filters**.

## Look up a window or an API

If you know the window but need its process, open **Window Spy** and drag **Find window** onto it. You can inspect the owning process and thread or log the window’s messages.

Open **Catalog** to look up API signatures, parameter types, and the rules used to recognize failed calls. Saved edits apply to the next capture that uses that catalog.

## License

Third-party notices are included in the `licenses` folder. Detourist is distributed under the [GNU General Public License v3.0 only](LICENSE).
