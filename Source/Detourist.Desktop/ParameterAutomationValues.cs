namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private const uint VariantTypeMask = 0xFFF;
    private const uint VariantPointerMask = 0x6000;
    private const int SafeArrayBoundSize = 8;

    private static ParameterType AutomationType(uint type) => (type & VariantTypeMask) switch
    {
        2 => new("Int16", 16, true), 3 or 22 => new("Int32", 32, true),
        4 => new("Float32", 32, Kind: "Float32"), 5 or 7 => new("Float64", Kind: "Float64"),
        6 => new("CY", 64, true), 8 => new("BSTR", Kind: "Pointer"),
        9 => new("IDispatch *", Kind: "Pointer"), 10 => new("SCODE", 32, true),
        11 => new("VARIANT_BOOL", 16, Kind: "Boolean"), 12 => new("VARIANT", Kind: "Structure"),
        13 => new("IUnknown *", Kind: "Pointer"), 14 => new("DECIMAL", Kind: "Structure"),
        16 => new("Int8", 8, true), 17 => new("UInt8", 8), 18 => new("UInt16", 16),
        19 or 23 => new("UInt32", 32), 20 => new("Int64", 64, true), 21 => new("UInt64"),
        _ => new("Bytes", Kind: "Structure")
    };

    private static void AddAutomationArrays(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        var beforeDescriptors = inputs.Where(value => value.Kind == (int)ValueKind.SafeArray).ToArray();
        var afterDescriptors = outputs.Where(value => value.Kind == (int)ValueKind.SafeArray).ToArray();
        var beforeData = inputs.Where(value => value.Kind == (int)ValueKind.SafeArrayData).ToArray();
        var afterData = outputs.Where(value => value.Kind == (int)ValueKind.SafeArrayData).ToArray();
        var indexes = beforeDescriptors.Concat(afterDescriptors).Select(value => value.ArrayIndex).Distinct().ToArray();
        var count = indexes.Length;
        ParameterProperty AddField(ParameterProperty owner, string name, ParameterType type, int offset, int size)
        {
            var field = Field(owner, name, type, offset, size);
            if (field.Input is null) field.InputLabel = Missing(owner.InputMemory, offset, size);
            if (field.Output is null) field.OutputLabel = Missing(owner.OutputMemory, offset, size);
            owner.Children.Add(field);
            return field;
        }
        for (var region = 0; region < count; ++region)
        {
            var before = beforeDescriptors.FirstOrDefault(value => value.ArrayIndex == indexes[region]);
            var after = afterDescriptors.FirstOrDefault(value => value.ArrayIndex == indexes[region]);
            var descriptor = after ?? before;
            if (descriptor is null) continue;
            var array = AddCapturedNode(parent, count == 1 ? "SAFEARRAY" : $"SAFEARRAY [{region}]",
                new("SAFEARRAY", Kind: "Structure"),
                before, after);
            AddField(array, "cDims", new("UInt16", 16), 0, 2);
            AddField(array, "fFeatures", new("UInt16", 16), 2, 2);
            AddField(array, "cbElements", new("UInt32", 32), 4, 4);
            AddField(array, "cLocks", new("UInt32", 32), 8, 4);
            var pointerOffset = ApiMetadata.PointerSize == 8 ? 16 : 12;
            var boundsOffset = pointerOffset + ApiMetadata.PointerSize;
            AddField(array, "pvData", new("Pointer", Kind: "Pointer"), pointerOffset, ApiMetadata.PointerSize);

            // Bounds and values expand only as far as complete or partial captured bytes permit.
            var dimensions = (int)MemorySnapshot.Scalar(descriptor.Bytes, 0, 2);
            var capturedDimensions = Math.Min(dimensions,
                Math.Max(0, (descriptor.Bytes.Length - boundsOffset + SafeArrayBoundSize - 1) / SafeArrayBoundSize));
            for (var dimension = 0; dimension < capturedDimensions; ++dimension)
            {
                var bound = AddCapturedNode(array, $"rgsabound[{dimension}]", new("SAFEARRAYBOUND", Kind: "Structure"),
                    Slice(before, boundsOffset + dimension * SafeArrayBoundSize, SafeArrayBoundSize),
                    Slice(after, boundsOffset + dimension * SafeArrayBoundSize, SafeArrayBoundSize), parent.Hex);
                AddField(bound, "cElements", new("UInt32", 32), 0, 4);
                AddField(bound, "lLbound", new("Int32", 32, true), 4, 4);
            }
            if (dimensions > capturedDimensions)
                array.Children.Add(new()
                {
                    Name = "Bounds", SignatureType = new("SAFEARRAYBOUND[]"), Level = array.Level + 1,
                    InputLabel = "<not fully captured>", OutputLabel = "<not fully captured>"
                });
            var arrayIndex = descriptor.ArrayIndex;
            var input = arrayIndex >= 0 ? beforeData.FirstOrDefault(value => value.ArrayIndex == arrayIndex) :
                beforeData.ElementAtOrDefault(region);
            var output = arrayIndex >= 0 ? afterData.FirstOrDefault(value => value.ArrayIndex == arrayIndex) :
                afterData.ElementAtOrDefault(region);
            var data = output ?? input;
            if (data is null) continue;
            var type = AutomationType(data.Flags >> 16);
            var bytes = (int)MemorySnapshot.Scalar(descriptor.Bytes, 4, 4);
            if (bytes <= 0) continue;
            var elements = AddCapturedNode(array, "Elements", new(type.Name + "[]"),
                input, output, parent.Hex);
            var available = Math.Max(input?.Bytes.Length ?? 0, output?.Bytes.Length ?? 0);
            var total = Math.Max(input?.OriginalBytes ?? 0, output?.OriginalBytes ?? 0) / (uint)bytes;
            var visible = (int)Math.Min(total, (ulong)Math.Min(Protocol.MaxExpandedElements,
                (available + (long)bytes - 1) / bytes));
            for (var index = 0; index < visible; ++index)
            {
                var value = AddCapturedNode(elements, $"[{index}]", type,
                    Slice(input, index * bytes, bytes), Slice(output, index * bytes, bytes), parent.Hex);
                if (type.Name == "VARIANT" && bytes == (ApiMetadata.PointerSize == 8 ? 24 : 16))
                {
                    AddField(value, "vt", new("VARTYPE", 16), 0, 2);
                    var variant = value.OutputMemory ?? value.InputMemory;
                    var tag = variant is null ? 0u : (uint)MemorySnapshot.Scalar(variant.Bytes, 0, 2);
                    var scalar = (tag & VariantPointerMask) != 0 ? new ParameterType("Pointer", Kind: "Pointer") :
                        AutomationType(tag);
                    if (scalar.Kind != "Structure") AddField(value, "Value", scalar, 8, scalar.Bits / 8);
                }
                else if (type.Kind != "Structure" && bytes == type.Bits / 8)
                {
                    value.Input = value.InputMemory is { } a && a.Bytes.Length == bytes ?
                        MemorySnapshot.Scalar(a.Bytes, 0, bytes) : null;
                    value.Output = value.OutputMemory is { } b && b.Bytes.Length == bytes ?
                        MemorySnapshot.Scalar(b.Bytes, 0, bytes) : null;
                    if (value.Input is null) value.InputLabel = Missing(value.InputMemory, 0, bytes);
                    if (value.Output is null) value.OutputLabel = Missing(value.OutputMemory, 0, bytes);
                }
            }
            if ((ulong)visible < total)
                elements.Children.Add(new()
                {
                    Name = $"[{visible}…{total - 1}]", SignatureType = type, Level = elements.Level + 1,
                    InputLabel = $"{total - (ulong)visible:N0} more elements",
                    OutputLabel = $"{total - (ulong)visible:N0} more elements"
                });
        }
    }

    private static void AddPropertyVectors(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        var indexes = inputs.Concat(outputs).Where(value => value.Kind == (int)ValueKind.PropertyVector)
            .Select(value => value.ArrayIndex).Distinct().ToArray();
        foreach (var index in indexes)
        {
            var before = inputs.FirstOrDefault(value => value.Kind == (int)ValueKind.PropertyVector &&
                value.ArrayIndex == index);
            var after = outputs.FirstOrDefault(value => value.Kind == (int)ValueKind.PropertyVector &&
                value.ArrayIndex == index);
            var descriptor = after ?? before;
            if (descriptor is null) continue;
            var vector = AddCapturedNode(parent, indexes.Length == 1 ? "Vector" : $"Vector [{index}]",
                new("Counted property vector", Kind: "Structure"),
                before, after);
            foreach (var (name, fieldType, offset, size) in new[] { ("cElems", new ParameterType("UInt32", 32), 0, 4),
                ("pElems", new ParameterType("Pointer", Kind: "Pointer"),
                    ApiMetadata.PointerSize, ApiMetadata.PointerSize) })
            {
                var field = Field(vector, name, fieldType, offset, size);
                if (field.Input is null) field.InputLabel = Missing(before, offset, size);
                if (field.Output is null) field.OutputLabel = Missing(after, offset, size);
                vector.Children.Add(field);
            }
            var input = inputs.FirstOrDefault(value => value.Kind == (int)ValueKind.PropertyVectorData &&
                value.ArrayIndex == index);
            var output = outputs.FirstOrDefault(value => value.Kind == (int)ValueKind.PropertyVectorData &&
                value.ArrayIndex == index);
            var sample = output ?? input;
            if (sample is null) continue;
            var tag = sample.Flags >> 16;
            var type = tag switch
            {
                2 => "SHORT", 3 => "LONG", 4 => "FLOAT", 5 or 7 => "DOUBLE", 6 => "CY", 8 => "BSTR",
                10 => "SCODE", 11 => "VARIANT_BOOL", 12 => "PROPVARIANT", 16 => "CHAR", 17 => "BYTE",
                18 => "USHORT", 19 => "DWORD", 20 => "LONGLONG", 21 => "ULONGLONG", 22 => "INT", 23 => "UINT",
                30 => "LPSTR", 31 => "LPWSTR", 64 => "FILETIME", 71 => "CLIPDATA", 72 => "GUID", _ => ""
            };
            var layout = ApiMetadata.Type(type);
            if (layout is not { Size: > 0 }) continue;
            var bytes = Math.Max(input?.OriginalBytes ?? 0, output?.OriginalBytes ?? 0);
            var array = new TypeLayout("Array", (int)Math.Min(bytes, int.MaxValue), type + "[]", type,
                (int)Math.Min(bytes / (uint)layout.Size, int.MaxValue));
            var elements = AddCapturedNode(vector, "Elements", new(type + "[]"),
                input, output, parent.Hex);
            AddArray(elements, array, input, output, 0, 0);
            if (tag == 11)
                foreach (var element in elements.Children)
                    element.SignatureType = new("VARIANT_BOOL", 16, Kind: "Boolean");
        }
    }

    private static void AddAutomationReference(ParameterProperty element, MemorySnapshot? input,
        MemorySnapshot? output, int fallbackType = -1)
    {
        var sample = output ?? input!;
        var tag = sample.VariantType < 0 ? fallbackType : sample.VariantType & (int)VariantTypeMask;
        var text = tag is 8 or 30 or 31;
        var layout = sample.Kind == (int)ValueKind.PropertyClipboard ? ApiMetadata.Structure("CLIPDATA") :
            tag == 72 ? ApiMetadata.Structure("GUID") : tag == 14 ? ApiMetadata.Structure("DECIMAL") : null;
        var type = text ? tag == 8 ? "BSTR" : tag == 30 ? "LPSTR" : "LPWSTR" : layout?.Name ?? sample.TypeName;
        var reference = new ParameterProperty
        {
            Name = text ? "Text" : sample.Kind == (int)ValueKind.PropertyClipboard ? "Clipboard" : "Data",
            SignatureType = ParameterType.Infer(type), Level = element.Level + 1,
            InputMemory = input, OutputMemory = output, Hex = element.Hex,
            InputLabel = text && input is not null ?
                QuotedText(input with
                {
                    Flags = tag == 8 ? input.Flags | (uint)ValueFlags.AutomationElement :
                        input.Flags & ~(uint)ValueFlags.AutomationElement
                }) : null,
            OutputLabel = text && output is not null ?
                QuotedText(output with
                {
                    Flags = tag == 8 ? output.Flags | (uint)ValueFlags.AutomationElement :
                        output.Flags & ~(uint)ValueFlags.AutomationElement
                }) : null
        };
        if (sample.Kind == (int)ValueKind.Scalar)
        {
            reference.SignatureType = AutomationType((uint)tag);
            reference.Input = input is { Bytes.Length: > 0 and <= 8 } ?
                MemorySnapshot.Scalar(input.Bytes, 0, input.Bytes.Length) : null;
            reference.Output = output is { Bytes.Length: > 0 and <= 8 } ?
                MemorySnapshot.Scalar(output.Bytes, 0, output.Bytes.Length) : null;
        }
        element.Children.Add(reference);
        if (layout is not null) AddFields(reference, layout, input, output);
    }

    private static void AddAutomationReferences(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        // Scalar allocations retain their resolved type and their exact array element, including invalid pointees.
        foreach (var array in parent.Children.Where(value =>
            (value.OutputMemory ?? value.InputMemory)?.Kind is (int)ValueKind.SafeArray or (int)ValueKind.PropertyVector))
        {
            var descriptor = (array.OutputMemory ?? array.InputMemory)!;
            var elements = array.Children.FirstOrDefault(value => value.Name == "Elements");
            if (elements is null) continue;
            var before = inputs.Where(value => array.InputMemory is not null &&
                (value.Flags & (uint)ValueFlags.AutomationElement) != 0 &&
                value.ArrayIndex == descriptor.ArrayIndex).ToArray();
            var after = outputs.Where(value => array.OutputMemory is not null &&
                (value.Flags & (uint)ValueFlags.AutomationElement) != 0 &&
                value.ArrayIndex == descriptor.ArrayIndex).ToArray();
            foreach (var key in before.Concat(after).Select(value => (value.ElementIndex, value.Kind)).Distinct())
            {
                if ((descriptor.Flags >> 16) == 71 && key.Kind == (int)ValueKind.PropertyClipboard) continue;
                var element = elements.Children.FirstOrDefault(value => value.Name == $"[{key.ElementIndex}]");
                if (element is null) continue;
                AddAutomationReference(element,
                    before.FirstOrDefault(value => value.ElementIndex == key.ElementIndex && value.Kind == key.Kind),
                    after.FirstOrDefault(value => value.ElementIndex == key.ElementIndex && value.Kind == key.Kind),
                    (int)(descriptor.Flags >> 16));
            }
        }
    }

    private static void LinkAutomationArrays(ParameterProperty parent)
    {
        // Both container kinds are built before nesting, so mixed graphs need no construction-order assumptions.
        var arrays = parent.Children.Where(value =>
            (value.OutputMemory ?? value.InputMemory)?.Kind is (int)ValueKind.SafeArray or (int)ValueKind.PropertyVector)
            .GroupBy(value => (value.OutputMemory ?? value.InputMemory)!.ArrayIndex)
            .Where(group => group.Count() == 1).ToDictionary(group => group.Key, group => group.Single());
        foreach (var (index, array) in arrays)
        {
            var descriptor = (array.OutputMemory ?? array.InputMemory)!;
            if (descriptor.ParentElementIndex < 0 || array.InputMemory is { } before &&
                array.OutputMemory is { } after && (before.ParentArrayIndex != after.ParentArrayIndex ||
                before.ParentElementIndex != after.ParentElementIndex)) continue;
            var visited = new HashSet<int> { index };
            var ancestor = descriptor.ParentArrayIndex;
            while (arrays.TryGetValue(ancestor, out var node) && visited.Add(ancestor))
                ancestor = (node.OutputMemory ?? node.InputMemory)!.ParentArrayIndex;
            if (visited.Contains(ancestor)) continue;
            var owner = arrays.GetValueOrDefault(descriptor.ParentArrayIndex);
            var elements = owner?.Children.FirstOrDefault(value => value.Name == "Elements")?.Children ??
                (descriptor.ParentArrayIndex < 0 ? parent.Children.Where(value =>
                    (value.OutputMemory ?? value.InputMemory)?.Kind == (int)ValueKind.Bytes)
                    .SelectMany(value => value.Children) : []);
            var element = elements.FirstOrDefault(value => value.Name == $"[{descriptor.ParentElementIndex}]");
            if (element is null) continue;
            parent.Children.Remove(array);
            element.Children.Add(array);
        }

        // Indentation follows the final bounded hierarchy, including fields below a moved container.
        void SetLevels(ParameterProperty owner)
        {
            foreach (var child in owner.Children)
            {
                child.Level = owner.Level + 1;
                SetLevels(child);
            }
        }
        if (arrays.Count != 0) SetLevels(parent);
    }
}
