# Detourist

Detourist is a Windows desktop API tracing tool for x64 and x86 programs. It records calls, arguments, return values, timing, and optional call stacks in SQLite trace files. The desktop app provides filtering, summaries, a timeline, parameter inspection, an API catalog editor, and Window Spy.

## Build and run

Install the Visual Studio C++ desktop toolchain and Windows SDK selected in `CMakePresets.json`, the .NET SDK selected in `global.json`, Python, and WiX matching the major version checked by `Build/Build.ps1`. The native profiler also requires the .NET Framework SDK headers and libraries. CMake uses pinned dependency downloads, so a first build needs network access.

From the repository root, build both architectures, run the tests, and assemble the desktop app:

```powershell
.\Build\Build.cmd -Test
```

Run `Build\PackageStage\Detourist.exe`. Keep the entire staged directory together, including its `x86` subdirectory, API catalogs, and instruction runtime files. The build also produces a portable ZIP and an MSI under `Build\Output`.

The build accepts `-Configuration`, `-BuildJobs`, and `-Version`. Omit `-Test` to skip executing tests. `Build/PackageStage` is rebuilt during packaging; build and test failures before staging preserve the existing package. Signing is optional: use `-Sign` with `-CertificateThumbprint` and `-TimestampUrl`, or their `DETOURIST_SIGNING_CERTIFICATE_THUMBPRINT` and `DETOURIST_TIMESTAMP_URL` environment variables.

For native development without packaging, use the configured Visual Studio installation's CMake and CTest tools:

```powershell
cmake --preset windows-x64
cmake --build --preset x64-release
ctest --preset x64-release

cmake --preset windows-x86
cmake --build --preset x86-release
ctest --preset x86-release
```

The native executables are written to `Build\Temp\x64\bin\Release` and `Build\Temp\x86\bin\Release`. Building the WPF project alone does not stage the collector and its runtime dependencies; use the packaging workflow to run the complete desktop app. Tests exercise local fixture programs, and some require an interactive Windows desktop or optional platform components.

## Work with traces

1. Open **Settings** to choose capture sources, categories, buffer limits, and optional stacks.
2. Use **Launch** for a new program or **Attach** for a running program. The app selects the matching collector architecture.
3. Select a call to inspect its inputs, outputs, and available stack information. Use display filters, **Find**, **Summary**, and the timeline to navigate recorded calls.
4. Use **Stop** to end recording and release the target. Open the saved database later with **Open trace** or by dropping it into the window.

Traces default to `%LOCALAPPDATA%\Detourist\Traces`; change the trace folder in Settings. Desktop preferences are stored in `%LOCALAPPDATA%\Detourist\Desktop.json`. Capture settings control what gets recorded; display filters only change which recorded calls are shown. Coverage depends on the selected engine, target architecture, available providers, and catalog metadata; inspect **Coverage** for the session's reported status.

## Catalog maintenance

The desktop **Catalog** window opens the catalog beside the application. Saved edits apply to the next capture session without rebuilding. Use **Open catalog** to edit another copy; x86 captures use the catalog in the application's `x86` subdirectory. The **Architecture** selector changes which architecture's metadata you edit within the open file.

To maintain the repository catalog, open `Source\catalog\ApiCatalog.sqlite` in the editor, then rebuild and stage the application to deploy those changes. Packaging replaces the staged catalogs with copies of the repository catalog.

## Source layout

- `Source`: desktop interface, collectors, capture engines, shared code, and API catalogs.
- `Build`: build entry points, installer inputs, and catalog generation scripts. Intermediate files are under `Build/Temp`; distributions are under `Build/Output`.
- `Test`: native and managed fixtures, desktop regressions, catalog checks, and integration tests.

The project license is in `LICENSE`; packaged third-party notices are in `licenses`.
