using System.IO;
using System.Runtime.InteropServices;

namespace Detourist.Desktop;

internal static class SqliteNative
{
    private const string Library = "DetouristSqlite.dll";
    internal const int SqliteRow = 100;
    internal const int SqliteDone = 101;
    internal const int OpenReadOnlyUri = 1 | 0x8000;
    internal const int OpenReadWriteUri = 2 | 0x8000;
    internal const int ColumnTypeInteger = 1;
    internal const int ColumnTypeFloat = 2;
    internal const int ColumnTypeText = 3;
    internal const int ColumnTypeBlob = 4;

    internal static void Check(nint database, int result)
    {
        if (result != 0) throw new IOException("API catalog: " +
            (database != 0 ? Marshal.PtrToStringUTF8(ErrorMessage(database)) : "Cannot open SQLite catalog."));
    }

    internal static string Text(nint statement, int column) =>
        Marshal.PtrToStringUTF8(ColumnText(statement, column)) ?? "";

    internal static int SelectArchitecture(nint database, int pointerSize, bool writable = false)
    {
        if (pointerSize is not (4 or 8)) throw new ArgumentOutOfRangeException(nameof(pointerSize));
        if (pointerSize == 8) return 0;

        // Select stored records; temporary views and edit triggers belong only to this connection.
        var result = Prepare(database, "SELECT sql FROM sqlite_schema WHERE type='view' OR " +
            (writable ? "(type='trigger' AND tbl_name IN (SELECT name FROM sqlite_schema WHERE type='view'))" : "0") +
            " ORDER BY type DESC,name", -1, out var statement, 0);
        if (result != 0) return result;
        var definitions = new List<string>();
        try
        {
            while ((result = Step(statement)) == SqliteRow)
                definitions.Add(Text(statement, 0));
        }
        finally { FinalizeStatement(statement); }
        if (result != SqliteDone) return result;
        foreach (var definition in definitions)
        {
            var sql = definition.Insert(7, "TEMP ").Replace("/*architecture*/8", "4");
            result = Exec(database, sql, 0, 0, out var error);
            if (error != 0) Free(error);
            if (result != 0) return result;
        }
        return 0;
    }

    [DllImport(Library, EntryPoint = "sqlite3_open_v2", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out nint database, int flags,
        nint vfs);
    [DllImport(Library, EntryPoint = "sqlite3_close_v2", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Close(nint database);
    [DllImport(Library, EntryPoint = "sqlite3_db_readonly", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int DatabaseReadOnly(nint database, [MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport(Library, EntryPoint = "sqlite3_busy_timeout", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int BusyTimeout(nint database, int milliseconds);
    [DllImport(Library, EntryPoint = "sqlite3_prepare_v2", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Prepare(nint database, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, int bytes,
        out nint statement, nint tail);
    [DllImport(Library, EntryPoint = "sqlite3_bind_text", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int BindText(nint statement, int index, [MarshalAs(UnmanagedType.LPUTF8Str)] string value,
        int bytes, nint destructor);
    [DllImport(Library, EntryPoint = "sqlite3_bind_int64", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int BindInteger(nint statement, int index, long value);
    [DllImport(Library, EntryPoint = "sqlite3_bind_null", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int BindNull(nint statement, int index);
    [DllImport(Library, EntryPoint = "sqlite3_step", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Step(nint statement);
    [DllImport(Library, EntryPoint = "sqlite3_column_count", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ColumnCount(nint statement);
    [DllImport(Library, EntryPoint = "sqlite3_column_type", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ColumnType(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_column_int64", CallingConvention = CallingConvention.Cdecl)]
    internal static extern long ColumnInteger(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_column_double", CallingConvention = CallingConvention.Cdecl)]
    internal static extern double ColumnDouble(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_column_text", CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint ColumnText(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_column_blob", CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint ColumnBlob(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_column_bytes", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ColumnBytes(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_changes", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Changes(nint database);
    [DllImport(Library, EntryPoint = "sqlite3_finalize", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int FinalizeStatement(nint statement);
    [DllImport(Library, EntryPoint = "sqlite3_errmsg", CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint ErrorMessage(nint database);
    [DllImport(Library, EntryPoint = "sqlite3_exec", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Exec(nint database, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql,
        nint callback, nint argument, out nint error);
    [DllImport(Library, EntryPoint = "sqlite3_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Free(nint pointer);
    [DllImport(Library, EntryPoint = "sqlite3_column_int", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Integer(nint statement, int column);
    [DllImport(Library, EntryPoint = "sqlite3_reset", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Reset(nint statement);
}
