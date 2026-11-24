# Build Detourist from source

Run these commands from the repository root on Windows. Install the Visual Studio C++ desktop toolchain, Windows SDK, .NET SDK, Python, and WiX. The native profiler also requires the .NET Framework SDK headers and libraries. The first build downloads pinned dependencies. The required tool versions are specified in the [CMake presets](../CMakePresets.json), [.NET SDK settings](../global.json), and [packaging script](Build.ps1).

## Build and package

This command builds both architectures, runs the tests, and packages the desktop app.

```powershell
.\Build\Build.cmd -Test
```

Run `Build\PackageStage\Detourist.exe` to try the complete app. The portable ZIP and MSI are written to `Build\Output`. Packaging recreates `Build\PackageStage` with the desktop app, both collectors, the API catalogs, and the instruction runtime files.

The build accepts `-Configuration`, `-BuildJobs`, and `-Version`. Omit `-Test` to skip the test suites. Some tests require an interactive Windows desktop or optional Windows components.

For a signed package, pass `-Sign`, `-CertificateThumbprint`, and `-TimestampUrl`. You can also supply the thumbprint and timestamp URL through the `DETOURIST_SIGNING_CERTIFICATE_THUMBPRINT` and `DETOURIST_TIMESTAMP_URL` environment variables.

## Build the native components

Use the Visual Studio installation’s CMake and CTest tools to build and test a single architecture.

```powershell
cmake --preset windows-x64
cmake --build --preset x64-release
ctest --preset x64-release
```

For x86, use `windows-x86` and `x86-release`. Native executables are written to `Build\Temp\x64\bin\Release` and `Build\Temp\x86\bin\Release`.

The repository API catalog is `Source\catalog\ApiCatalog.sqlite`. To update the catalog distributed with the application, edit that file in **Catalog** and rebuild the packages.
