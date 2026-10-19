using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    public static List<ParameterProperty> Build(JsonElement call, bool breakpoint = false,
        bool leaving = false, bool rawSlots = false)
    {
        using var architecture = ApiMetadata.UsePointerSize((int)call.Number("pointerSize", 8));
        var runtimeLayouts = new Dictionary<int, TypeLayout>();
        TypeLayout? runtimeResult = null;
        var layoutText = call.Text("layout");
        if (layoutText.Length > 0)
        {
            using var document = JsonDocument.Parse(layoutText);
            var descriptor = document.RootElement;
            var types = descriptor.Items("Types");
            if (types.Length == 0) types = [descriptor];

            // Descriptor indexes distinguish equal field type names from different assemblies.
            TypeLayout Layout(JsonElement type, int depth = 0) => new("Structure", (int)type.Number("Size"),
                type.Text("Name"), Fields: type.Items("Fields").Select(field =>
                {
                    var nested = field.GetArrayLength() > 4 && field[4].ValueKind == JsonValueKind.Number &&
                        field[4].TryGetInt32(out var reference) && (uint)reference < (uint)types.Length ?
                        types[reference] : default;
                    return new TypeField(field[0].GetString() ?? "", field[1].GetString() ?? "",
                        field[2].GetInt32() * 8, field[3].GetInt32() * 8,
                        depth < Protocol.MaxExpansionDepth && nested.ValueKind == JsonValueKind.Object ?
                            Layout(nested, depth + 1) : null);
                }).ToArray());
            TypeLayout? Reference(JsonElement reference)
            {
                var array = reference.ValueKind == JsonValueKind.Object && reference.TryGetProperty("Element", out _);
                var index = array ? reference.GetProperty("Element") : reference;
                if (index.ValueKind != JsonValueKind.Number || !index.TryGetInt32(out var position) ||
                    (uint)position >= (uint)types.Length) return null;
                var element = Layout(types[position]);
                var rank = array ? Math.Clamp((int)reference.Number("Rank", 1), 1, 32) : 0;
                return array ? new("Array", 0, element.Name + "[" + new string(',', rank - 1) + "]",
                    element.Name, ElementLayout: element) : element;
            }
            if (descriptor.TryGetProperty("Arguments", out var mapping))
            {
                var index = 0;
                foreach (var reference in mapping.EnumerateArray())
                {
                    if (Reference(reference) is { } layout) runtimeLayouts[index] = layout;
                    ++index;
                }
                if (descriptor.TryGetProperty("Result", out var returnMapping))
                    runtimeResult = Reference(returnMapping);
            }
            else runtimeLayouts[0] = Layout(descriptor);
        }
        var signature = call.Text("parameters");
        var arrow = signature.LastIndexOf(" -> ", StringComparison.Ordinal);
        var resultType = arrow < 0 ? "uintptr_t" : signature[(arrow + 4)..];
        if (runtimeResult is not null) resultType = runtimeResult.Name + (resultType.EndsWith('&') ? "&" : "");
        if (arrow >= 0) signature = signature[..arrow];
        if (arrow >= 0 && signature.StartsWith("Raw CLR argument regions; ", StringComparison.Ordinal))
            signature = signature["Raw CLR argument regions; ".Length..];
        var managed = Protocol.IsManagedApi(call.Number("api"));
        var declarations = Split(signature);
        var functionName = call.Text("name");
        var definition = ApiMetadata.Function(functionName, call.Text("module"), call.Text("parameters"));
        var parameters = definition?.Parameters ?? declarations.Select((declaration, index) =>
        {
            var (name, type) = Declaration(declaration, index);
            return new ApiParameter(name, type);
        }).ToArray();
        if (definition is not null) resultType = definition.Result;
        var consumedArguments = call.Items("arguments");
        var arguments = rawSlots && call.TryGetProperty("rawArguments", out _) ?
            call.Items("rawArguments") : consumedArguments;
        var avi = parameters.Length == 6 && call.Text("module").Equals("avifil32.dll",
            StringComparison.OrdinalIgnoreCase) && functionName is "AVISave" or "AVISaveA" or "AVISaveW";
        var aviStreams = avi && arguments.Length > 3 ? unchecked((int)new ParameterType("UInt64")
            .Parse(arguments[3].ToString(), true)) : 0;
        var aviObserved = Math.Clamp(aviStreams, 0, Math.Max(0, (consumedArguments.Length - 4) / 2));
        var audit = functionName == "AuthzReportSecurityEvent" &&
            call.Text("module").Equals("authz.dll", StringComparison.OrdinalIgnoreCase);
        var auditArguments = AuthzArguments(audit ? consumedArguments : []);
        var rpcArguments = RpcArguments(call);
        var rows = new List<ParameterProperty>();
        var input = ReadSnapshots(call, "input");
        var output = ReadSnapshots(call, "output");
        var completionOutput = output;
        if (call.TryGetProperty("completion", out var completion))
        {
            // Completed vector payloads describe their submission buffers, independently of caller-owned descriptors.
            var vectors = completion.Items("buffers").Where(buffer => buffer.Number("index") != uint.MaxValue)
                .Select(buffer => (uint)buffer.Number("parameter")).ToHashSet();
            if (vectors.Count != 0) output = output.ToDictionary(item => item.Key, item => vectors.Contains(item.Key) ?
                item.Value.Where(value => value.Kind != (int)ValueKind.Bytes ||
                    (value.Flags & (uint)ValueFlags.ReferencedData) == 0).ToList() : item.Value);
        }
        var raw = (call.Number("flags") & (long)EventFlags.RawArguments) != 0;
        var scanning = functionName.Contains("scanf", StringComparison.Ordinal);
        var common = functionName.Contains("_common_v", StringComparison.Ordinal);
        var options = common && arguments.Length > 0 ?
            ParameterType.ParseHex(arguments[0].ToString()) : 0;
        var legacyWide = !common || (options & (scanning ? 2u : 4u)) != 0;
        var secureScan = scanning && common && (options & 1) != 0;
        var ber = definition is not null && raw ?
            BerArguments(functionName, call.Text("module"), input, arguments.Length) : [];
        var countedTypes = new Dictionary<int, List<string>>();
        var formatted = definition is not null && raw ?
            FormatArguments(functionName, call.Text("module"), parameters, input,
                arguments.Length, legacyWide, countedTypes, secureScan) : [];
        if (definition is not null && raw && arguments.Length > 0 &&
            functionName is "OleUIPromptUserA" or "OleUIPromptUserW" &&
            System.IO.Path.GetFileName(call.Text("module")).Equals("oledlg.dll", StringComparison.OrdinalIgnoreCase))
            formatted = PromptArguments(functionName.EndsWith('W'),
                (uint)ParameterType.ParseHex(arguments[0].ToString()), arguments.Length);
        if (definition is not null && raw && arguments.Length > 2 && functionName == "WdsCliLog" &&
            System.IO.Path.GetFileName(call.Text("module")).Equals("wdsclientapi.dll",
                StringComparison.OrdinalIgnoreCase))
            formatted = WdsLogArguments((uint)ParameterType.ParseHex(arguments[2].ToString()),
                arguments.Length);
        var listed = definition is not null && raw ?
            ListArguments(functionName, parameters, arguments) : [];
        var argumentList = Array.FindIndex(parameters, parameter =>
            parameter.Name == "_ArgList" || parameter.Type == "va_list");
        var listValues = input.GetValueOrDefault((uint)argumentList, []);
        var listCount = listValues.Where(value => (value.Flags & 64) != 0)
            .Select(value => value.ElementIndex + 1).DefaultIfEmpty().Max();
        var listCountedTypes = new Dictionary<int, List<string>>();
        var listTypes = argumentList >= 0 && listCount > 0 ?
            FormatArguments(functionName, call.Text("module"), parameters, input,
                parameters.Length + listCount, legacyWide, listCountedTypes, secureScan)
                .ToDictionary(value => value.Key - parameters.Length, value => value.Value) : [];
        listCountedTypes = listCountedTypes.ToDictionary(value => value.Key - parameters.Length, value => value.Value);
        var modeIndex = Array.FindIndex(parameters, parameter => parameter.Name == "_PMode");
        var flagIndex = Array.FindIndex(parameters, parameter => parameter.Name == "_OFlag");
        var omittedOpenMode = modeIndex >= 0 && flagIndex >= 0 &&
            Regex.IsMatch(functionName, @"^_w?s?open$") && flagIndex < arguments.Length &&
            (ParameterType.ParseHex(arguments[flagIndex].ToString()) & 0x100) == 0;
        var sound = functionName is "PlaySound" or "PlaySoundA" or "PlaySoundW" or "sndPlaySoundA" or "sndPlaySoundW";
        var soundFlagIndex = functionName.StartsWith("snd", StringComparison.Ordinal) ? 1 : 2;
        var soundFlags = sound && arguments.Length > soundFlagIndex ?
            ParameterType.ParseHex(arguments[soundFlagIndex].ToString()) : 0;
        var structures = parameters.Select((parameter, index) => index < arguments.Length ?
            ParameterType.Infer(parameter.Type).Choices.FirstOrDefault(choice => choice.Value ==
                ParameterType.ParseHex(arguments[index].ToString()))?.Structures : null)
            .FirstOrDefault(types => types is { Length: > 0 });

        // A provisional declaration must not hide raw slots whose parameter identities remain unknown.
        var count = definition is null || raw ?
            Math.Max(arguments.Length, parameters.Length) : parameters.Length;
        for (var index = 0; index < count; ++index)
        {
            var berArgument = ber.GetValueOrDefault(index);
            var parameter = rpcArguments.GetValueOrDefault(index) ??
                auditArguments.Parameters.GetValueOrDefault(index) ??
                berArgument?.Parameter ?? listed.GetValueOrDefault(index) ??
                (index < parameters.Length ? parameters[index] :
                formatted.GetValueOrDefault(index) ?? new ApiParameter($"arg{index}", ""));
            if (avi && index >= 4 && index < 4 + aviObserved * 2)
                parameter = (index & 1) == 0 ? new($"streams[{(index - 4) / 2}]", "PAVISTREAM") :
                    new($"options[{(index - 5) / 2}]", "LPAVICOMPRESSOPTIONS");
            if (rawSlots && index >= consumedArguments.Length)
                parameter = new($"ABI slot {index}", "");
            if (omittedOpenMode && raw && index == modeIndex) parameter = new($"arg{index}", "");
            var (name, type) = parameter;
            var runtimeLayout = runtimeLayouts.GetValueOrDefault(index);
            if (runtimeLayout is not null) type = runtimeLayout.Name + (type.EndsWith('&') ? "&" : "");
            ulong? value = index < arguments.Length ?
                ParameterType.ParseHex(arguments[index].ToString()) : null;
            var array = runtimeLayout is { Kind: "Array" } ? runtimeLayout :
                ApiMetadata.Type(type) is { Kind: "Array" } arrayLayout ? arrayLayout : null;
            var captured = input.GetValueOrDefault((uint)index, []);
            if (functionName == "AddMRUStringW" && index == 1 && captured.Any(value => value.Kind == (int)ValueKind.Bytes))
                type = "const void *";
            if (sound && index == 0 && (soundFlags & 4) != 0 && (soundFlags & 0x40004) != 0x40004)
                type = "const void *";
            var aggregate = managed && !captured.Any(value => value.Kind == (int)ValueKind.Scalar) ?
                captured.FirstOrDefault(value => value.Kind == (int)ValueKind.Bytes && value.OriginalBytes > 8) : null;
            var structureValue = runtimeLayout is { Kind: "Structure" or "Union" } && !type.EndsWith('&');
            var property = new ParameterProperty
            {
                Name = $"[{index}] {name}", Parameter = index,
                SignatureType = array is null && !captured.Any(value => value.Kind == (int)ValueKind.ManagedArray) ?
                    ParameterType.Infer(type, name) : new(type, Kind: "Pointer"),
                Input = aggregate is null && !structureValue ? value : null,
                InputLabel = omittedOpenMode && index == modeIndex && !raw ? "<not supplied>" :
                    aggregate is not null ? $"<{aggregate.OriginalBytes}-byte value>" :
                    structureValue ? "<structure>" : value.HasValue ? null : "<not captured>", EditedValue = value ?? 0,
                Editable = breakpoint && !leaving && value.HasValue && aggregate is null && !structureValue
            };

            // AVI stream interfaces are identities rather than caller-owned structures.
            if (avi && index >= 4 && (index & 1) == 0)
            {
                rows.Add(property);
                continue;
            }
            var scannedScalar = functionName.Contains("scanf", StringComparison.OrdinalIgnoreCase) &&
                formatted.ContainsKey(index) && Regex.IsMatch(type,
                    @"^(?:U?Int(?:8|16|32|64)|Float(?:32|64)) \*$|^void \*\*$");
            var scannedBuffer = functionName.Contains("scanf", StringComparison.OrdinalIgnoreCase) &&
                (name.StartsWith("characters[", StringComparison.Ordinal) ||
                    name.StartsWith("buffer[", StringComparison.Ordinal));
            if (type == "PSID" && (audit || functionName == "AuthzReportSecurityEventFromParams" ||
                captured.Any(value => (value.Flags & (uint)ValueFlags.SidData) != 0)))
                AddNetApiSid(property, captured.FirstOrDefault(), null);
            else if (berArgument is not null)
                AddBerMemory(property, berArgument, captured, output.GetValueOrDefault((uint)index, []));
            else if (formatted.ContainsKey(index) && name.StartsWith("count[", StringComparison.Ordinal))
                AddFormatCount(property, type, captured, output.GetValueOrDefault((uint)index, []));
            else if (formatted.ContainsKey(index) && name.StartsWith("counted[", StringComparison.Ordinal))
                AddCountedFormatString(property, type, captured, countedTypes.GetValueOrDefault(index));
            else AddMemory(property, input.GetValueOrDefault((uint)index, []),
                output.GetValueOrDefault((uint)index, []),
                ApiMetadata.Type(type) is { Kind: "Pointer", Element: "void" or "VOID" } ? structures : null,
                scannedScalar || scannedBuffer ? new("Bytes", 0, "Raw capture") :
                    index == argumentList && type == "va_list" ? new("Bytes", 0, "Raw argument window") :
                    runtimeLayout,
                index == argumentList ? listTypes : null, index == argumentList ? listCountedTypes : null,
                scalarLayout: structureValue);

            // Family-independent route fields remain visible when the argument has no concrete structure type.
            if (call.Text("module").Equals("rtm.dll", StringComparison.OrdinalIgnoreCase) &&
                ApiMetadata.Structure(type) is null &&
                (index == 1 && functionName is ("RtmAddRoute" or "RtmDeleteRoute") ||
                 index == 2 && functionName == "RtmBlockDeleteRoutes"))
                foreach (var field in captured.Where(value => value.MemberOffset >= 0))
                    AddCapturedNode(property, $"field +0x{field.MemberOffset:X}", new(field.TypeName), field, null);

            // Sound names remain text when the capture limit cuts off their terminator.
            if (sound && index == 0 && type != "const void *")
                foreach (var child in property.Children)
                    if (child.InputMemory is { Kind: 0 or 1 } text)
                    {
                        child.InputLabel = QuotedText(text);
                        child.Children.Clear();
                    }

            // A formatter's local string contract also identifies a precision-limited, unterminated prefix as text.
            if (formatted.ContainsKey(index) && !functionName.Contains("scanf", StringComparison.OrdinalIgnoreCase) &&
                type is "char *" or "wchar_t *")
                foreach (var child in property.Children)
                    if (child.InputMemory is { Kind: 0 or 1 } text)
                        child.InputLabel = QuotedText(text, type == "wchar_t *");
            if (scannedScalar && !name.StartsWith("count[", StringComparison.Ordinal))
                AddScannedValue(property, type, captured, output.GetValueOrDefault((uint)index, []));
            var layout = ApiMetadata.Structure(type);
            if (berArgument is null && layout is not null && !captured.Concat(output.GetValueOrDefault((uint)index, []))
                .Any(value => (value.Flags & (uint)(ValueFlags.LdapData | ValueFlags.SyncAllData |
                    ValueFlags.ReplicaData)) != 0) && !property.Children.Any(child =>
                child.TypeName == layout.Name || child.TypeName == layout.Name + "[]"))
            {
                if (ApiMetadata.Type(type)?.Kind is "Structure" or "Union" && layout.Size is > 0 and <= 8)
                {
                    var inline = value.HasValue ? new MemorySnapshot(0, 0, (ulong)layout.Size,
                        BitConverter.GetBytes(value.Value)[..layout.Size]) : null;
                    AddFields(property, layout, inline, null);
                }
                else AddSnapshot(property, null, null, layout);
            }
            if (array is not null && property.Children.Count == 0) AddSnapshot(property, null, null, array);
            if (type.Length == 0 && property.Children.Count > 0)
                property.SignatureType = new(property.Children[0].TypeName + "*", Kind: "Pointer");
            rows.Add(property);
        }
        if (auditArguments.Captured < auditArguments.Requested)
            rows.Add(new()
            {
                Name = $"audit[{auditArguments.Captured}…{auditArguments.Requested - 1}]", Parameter = -3,
                SignatureType = new("AUDIT_PARAM_TYPE"), InputLabel = "<not captured>"
            });
        if (aviStreams > aviObserved)
            rows.Add(new()
            {
                Name = $"streams[{aviObserved}…{aviStreams - 1}]", Parameter = -3,
                SignatureType = new("PAVISTREAM, LPAVICOMPRESSOPTIONS"), InputLabel = "<not captured>"
            });
        var returned = breakpoint || call.Decimal("durationUs", -1) >= 0 &&
            (call.Number("flags") & (long)(EventFlags.Unwound | EventFlags.Continuation)) == 0;
        var returnValue = ParameterType.ParseHex(call.Text("result", "0x0"));
        var returnSnapshots = output.GetValueOrDefault(uint.MaxValue, []);
        var returnAggregate = managed && !returnSnapshots.Any(value => value.Kind == (int)ValueKind.Scalar) ?
            returnSnapshots.FirstOrDefault(value => value.Kind == (int)ValueKind.Bytes && value.OriginalBytes > 8) : null;
        var returnStructure = returnAggregate is not null ||
            runtimeResult is { Kind: "Structure" or "Union" } && !resultType.EndsWith('&') ||
            ApiMetadata.Type(resultType)?.Kind is "Structure" or "Union";
        var result = new ParameterProperty
        {
            Name = "$return", Parameter = -1,
            SignatureType = returnSnapshots.Any(value => value.Kind == (int)ValueKind.ManagedArray) ?
                new(resultType, Kind: "Pointer") : ParameterType.Infer(resultType),
            Output = returned && !returnStructure && resultType != "void" && resultType != "VOID" ? returnValue : null,
            OutputLabel = resultType is "void" or "VOID" ? "<void>" : returned ?
                returnAggregate is not null ? $"<{returnAggregate.OriginalBytes}-byte value>" :
                returnStructure ? "<structure>" : null : "<not observed>",
            EditedValue = returnValue,
            Editable = breakpoint && !returnStructure && resultType is not "void" and not "VOID",
            Hex = ParameterType.Infer(resultType).Kind is not "Float32" and not "Float64"
        };
        AddMemory(result, [], output.GetValueOrDefault(uint.MaxValue, [])
            .Where(value => value.Kind != (int)ValueKind.Stack).ToList(),
            declaredLayout: runtimeResult, scalarLayout: runtimeResult is { Kind: "Structure" or "Union" } &&
                !resultType.EndsWith('&'));

        // Referenced ANSI return values retain their declared string type and bounded text.
        if (ApiMetadata.Type(resultType) is { Kind: "Pointer", Element: "char" or "CHAR" })
            foreach (var child in result.Children)
                if (child.OutputMemory is { Kind: (int)ValueKind.Bytes } text &&
                    (text.Flags & (uint)ValueFlags.ReferencedData) != 0)
                {
                    child.SignatureType = new(resultType, Kind: "Pointer");
                    child.OutputLabel = QuotedText(text);
                    child.Children.Clear();
                }
        if (returnStructure && result.Children.Count == 0 && ApiMetadata.Structure(resultType) is { } returnLayout)
        {
            var inline = returned && !call.Text("module").Equals("COM", StringComparison.OrdinalIgnoreCase) &&
                returnLayout.Size is > 0 and <= 8 ? new MemorySnapshot(0, 0, (ulong)returnLayout.Size,
                    BitConverter.GetBytes(returnValue)[..returnLayout.Size]) : null;
            AddSnapshot(result, null, inline, returnLayout);
        }
        if (breakpoint && returnStructure && call.Text("module").Equals("COM", StringComparison.OrdinalIgnoreCase))
            result.Children.Add(new()
            {
                Name = "Return buffer", SignatureType = new(resultType + " *", Kind: "Pointer"),
                Level = 1, Output = returnValue
            });
        rows.Add(result);
        rows.Add(new()
        {
            Name = "LastError", SignatureType = new("UInt32", 32), Parameter = -2,
            Output = returned ? (ulong)call.Number("error") : null, OutputLabel = returned ? null : "<not observed>",
            EditedValue = (ulong)call.Number("error"), Editable = breakpoint, Hex = false
        });
        if (!breakpoint) AddAsyncCompletion(rows, call, completionOutput);
        AddRpcValues(rows, call);
        var stacks = input.GetValueOrDefault(uint.MaxValue, []).Where(value => value.Kind == 5).ToList();
        if (stacks.Count > 0)
        {
            var stack = new ParameterProperty { Name = "Call stack", SignatureType = new("Stack") };
            var frames = call.Items("stack");
            if (frames.Length == 0) AddMemory(stack, stacks, []);
            else for (var index = 0; index < frames.Length; ++index)
            {
                var frame = frames[index];
                var row = new ParameterProperty
                {
                    Name = $"[{index}]", SignatureType = new("Address", Kind: "Pointer"), Level = 1,
                    Input = ParameterType.ParseHex(frame.Text("address")),
                    InputLabel = frame.Text("display")
                };
                if (frame.Text("source") is { Length: > 0 } source) row.Children.Add(new()
                {
                    Name = "Source", SignatureType = new("Location"), Level = 2,
                    InputLabel = $"{source}:{frame.Number("line")}"
                });
                stack.Children.Add(row);
            }
            if (stacks.Any(value => (value.Flags & 1) != 0)) stack.InputLabel = "Partial stack";
            rows.Add(stack);
        }
        return rows;
    }

    private static Dictionary<uint, List<MemorySnapshot>> ReadSnapshots(JsonElement call, string name) =>
        call.Items(name).Where(value => value.Number("kind") is not 15 and not 16)
            .GroupBy(value => (uint)value.Number("parameter"))
            .ToDictionary(group => group.Key, group => group.Select(MemorySnapshot.FromJson).ToList());

    private static List<string> Split(string signature)
    {
        var values = new List<string>();
        var start = 0;
        var depth = 0;
        for (var index = 0; index < signature.Length; ++index)
        {
            var character = signature[index];
            if (character is '(' or '[' or '<') ++depth;
            else if (character is ')' or ']' or '>') depth = Math.Max(0, depth - 1);
            else if (character == ',' && depth == 0)
            {
                values.Add(signature[start..index].Trim());
                start = index + 1;
            }
        }
        if (start < signature.Length) values.Add(signature[start..].Trim());
        return values;
    }

    private static (string Name, string Type) Declaration(string declaration, int index)
    {
        if (declaration.Contains(';') || declaration.StartsWith("Raw ", StringComparison.OrdinalIgnoreCase))
            return ($"arg{index}", "");
        var colon = declaration.IndexOf(": ", StringComparison.Ordinal);
        if (colon >= 0) return (declaration[..colon].Trim(), declaration[(colon + 2)..].Trim());
        var name = Regex.Match(declaration, @"[A-Za-z_$][\w$]*(?:\[[^\]]*\])?$");
        return name.Success ? (name.Value, declaration[..name.Index].Trim()) : ($"arg{index}", "");
    }

    private static void AddMemory(ParameterProperty parent, List<MemorySnapshot> inputs, List<MemorySnapshot> outputs,
        string[]? structures = null, TypeLayout? declaredLayout = null,
        Dictionary<int, ApiParameter>? elementTypes = null, Dictionary<int, List<string>>? countedTypes = null,
        bool scalarLayout = false)
    {
        TypeLayout? Layout(MemorySnapshot? sample) => sample is { ReplicaType: >= 0 and < 12 } &&
            (sample.Flags & (128 | 512)) == 512 ? ReplicaLayout(sample.ReplicaType) :
            (sample?.Kind is 0 or 12 || scalarLayout && sample?.Kind == 2) && declaredLayout is not null ?
            declaredLayout : sample is null || structures is null ? null :
            structures.Select(ApiMetadata.Structure).Where(type => type is not null &&
                (ulong)type.Size <= sample.OriginalBytes).OrderByDescending(type => type!.Size).FirstOrDefault();

        // Automation descriptors and data remain paired independently of ordinary parameter regions.
        AddAutomationArrays(parent, inputs, outputs);
        AddPropertyVectors(parent, inputs, outputs);
        AddAutomationReferences(parent, inputs, outputs);
        AddLdapModifications(parent, inputs, outputs);
        AddLdapControls(parent, inputs, outputs);
        AddLdapBerValues(parent, inputs, outputs);
        AddLdapBerArrays(parent, inputs, outputs);
        AddEtwBuffers(parent, inputs, outputs);
        AddNetApiRecords(parent, inputs, outputs);
        AddSyncAllErrors(parent, inputs, outputs);
        AddAuthzAuditParameters(parent, inputs);
        AddAuthzAccessRequest(parent, inputs);
        AddSecurityDescriptors(parent, inputs, outputs);
        var stringsBefore = inputs.Where(value => (value.Flags & 64) != 0).ToList();
        var stringsAfter = outputs.Where(value => (value.Flags & 64) != 0).ToList();
        inputs = inputs.Where(value => value.Kind is not (8 or 9 or 10 or 11) && (value.Flags & 480) == 0 &&
            value.Structure.Length == 0 && value.EtwFormat < 0 && value.SecurityPart < 0 &&
            value.AuditPart < 0).ToList();
        outputs = outputs.Where(value => value.Kind is not (8 or 9 or 10 or 11) && (value.Flags & 480) == 0 &&
            value.Structure.Length == 0 && value.EtwFormat < 0 && value.SecurityPart < 0 &&
            value.AuditPart < 0).ToList();

        // Match snapshots by kind and occurrence; one parameter can reference several captured regions.
        var membersBefore = inputs.Where(value => value.MemberOffset >= 0).ToList();
        var membersAfter = outputs.Where(value => value.MemberOffset >= 0).ToList();
        inputs = inputs.Where(value => value.MemberOffset < 0).ToList();
        outputs = outputs.Where(value => value.MemberOffset < 0).ToList();
        var used = new HashSet<int>();
        foreach (var before in inputs)
        {
            var index = 0;
            while (index < outputs.Count && (used.Contains(index) || outputs[index].Kind != before.Kind)) ++index;
            if (index == outputs.Count) index = -1;
            if (index >= 0) used.Add(index);
            AddSnapshot(parent, before, index >= 0 ? outputs[index] : null, Layout(before));
        }

        // Expand typed allocations without reading beyond the returned buffer's captured bytes.
        TypeLayout? allocated = null;
        if (outputs.Any(value => value.Kind == 2) && ApiMetadata.Type(parent.SignatureType.Name) is
            { Kind: "Pointer", Element: { } pointerName } && ApiMetadata.Type(pointerName) is
            { Kind: "Pointer", Element: { } allocatedElementName } &&
            ApiMetadata.Type(allocatedElementName) is { Size: > 0 } allocatedElement)
        {
            var buffer = outputs.FirstOrDefault(value => value.Kind == 0);
            if (buffer is not null && buffer.OriginalBytes > (ulong)allocatedElement.Size &&
                buffer.OriginalBytes % (uint)allocatedElement.Size == 0)
                allocated = new("Array", (int)Math.Min(buffer.OriginalBytes, int.MaxValue),
                    (allocatedElement.Name ?? allocatedElementName) + "[]", allocatedElementName,
                    (int)Math.Min(buffer.OriginalBytes / (uint)allocatedElement.Size, int.MaxValue));
        }
        for (var index = 0; index < outputs.Count; ++index)
            if (!used.Contains(index)) AddSnapshot(parent, null, outputs[index],
                outputs[index].Kind == 0 ? allocated ?? Layout(outputs[index]) : Layout(outputs[index]));

        // Counted strings remain associated with their captured pointer-array elements.
        foreach (var index in stringsBefore.Concat(stringsAfter).Select(value => value.ElementIndex).Distinct())
        {
            var before = stringsBefore.Where(value => value.ElementIndex == index).ToList();
            var after = stringsAfter.Where(value => value.ElementIndex == index).ToList();
            var element = parent.Children.SelectMany(value => value.Children)
                .FirstOrDefault(value => value.Name == $"[{index}]") ?? parent;
            var scalarBefore = before.FirstOrDefault(value => value.Kind == 2);
            var scalarAfter = after.FirstOrDefault(value => value.Kind == 2);
            if (scalarBefore is not null || scalarAfter is not null)
            {
                var inferred = elementTypes?.GetValueOrDefault(index);
                var text = before.Concat(after).FirstOrDefault(value => value.Kind is 0 or 1 && (value.Flags & 8) != 0);
                var owner = element;
                element = new()
                {
                    Name = inferred is null ? $"Argument [{index}]" : $"[{index}] {inferred.Name}",
                    SignatureType = ParameterType.Infer(inferred?.Type ??
                        (text is null ? "UInt64" : text.Kind == 1 ? "wchar_t *" : "char *")),
                    InputMemory = scalarBefore, OutputMemory = scalarAfter,
                    Input = scalarBefore is { Bytes.Length: > 0 and <= 8 } ?
                        MemorySnapshot.Scalar(scalarBefore.Bytes, 0, scalarBefore.Bytes.Length) : null,
                    Output = scalarAfter is { Bytes.Length: > 0 and <= 8 } ?
                        MemorySnapshot.Scalar(scalarAfter.Bytes, 0, scalarAfter.Bytes.Length) : null,
                    Level = owner.Level + 1, Hex = parent.Hex
                };
                owner.Children.Add(element);
                before = before.Where(value => value.Kind != 2).ToList();
                after = after.Where(value => value.Kind != 2).ToList();
            }
            if (elementTypes?.GetValueOrDefault(index) is { } count &&
                count.Name.StartsWith("count[", StringComparison.Ordinal))
            {
                AddFormatCount(element, count.Type, before, after);
                continue;
            }
            if (elementTypes?.GetValueOrDefault(index) is { } countedString &&
                countedString.Name.StartsWith("counted[", StringComparison.Ordinal))
            {
                AddCountedFormatString(element, countedString.Type, before, countedTypes?.GetValueOrDefault(index));
                continue;
            }
            if (elementTypes?.GetValueOrDefault(index) is { } scanned &&
                (scanned.Name.StartsWith("characters[", StringComparison.Ordinal) ||
                    scanned.Name.StartsWith("buffer[", StringComparison.Ordinal) ||
                    scanned.Name.StartsWith("scan[", StringComparison.Ordinal) &&
                    scanned.Type is not ("char *" or "wchar_t *")))
            {
                if (scanned.Name.StartsWith("scan[", StringComparison.Ordinal))
                    AddScannedValue(element, scanned.Type, before, after);
                for (var region = 0; region < Math.Max(before.Count, after.Count); ++region)
                    AddSnapshot(element, before.ElementAtOrDefault(region), after.ElementAtOrDefault(region),
                        new("Bytes", 0, "Raw capture"));
                continue;
            }
            foreach (var kind in before.Concat(after).Select(value => value.Kind).Distinct())
            {
                var first = before.Where(value => value.Kind == kind).ToArray();
                var second = after.Where(value => value.Kind == kind).ToArray();
                for (var region = 0; region < Math.Max(first.Length, second.Length); ++region)
                {
                    var input = first.ElementAtOrDefault(region);
                    var output = second.ElementAtOrDefault(region);
                    var sample = output ?? input!;
                    if (sample.VariantType >= 0)
                    {
                        AddAutomationReference(element, input, output);
                        continue;
                    }
                    var declaredElement = ApiMetadata.Type(parent.SignatureType.Name)?.Element;
                    var counted = (sample.Flags & 32) != 0 || declaredElement == "BSTR" || element.TypeName == "BSTR";
                    var declaredText = ApiMetadata.Type(declaredElement ?? "") is
                        { Kind: "Pointer", Element: "char" or "CHAR" or "wchar_t" or "WCHAR" };
                    var text = elementTypes is not null || counted || declaredText;
                    var type = text && kind == 1 ? counted ? "BSTR" : "wchar_t *" :
                        text && kind == 0 ? "char *" : sample.TypeName;
                    element.Children.Add(new()
                    {
                        Name = element == parent ? $"String [{index}]" : region == 0 ? "Text" : $"Text [{region}]",
                        SignatureType = new(type, Kind: text ? "Pointer" : "Unknown"),
                        InputMemory = input, OutputMemory = output,
                        InputLabel = text && kind == 0 && input is not null ? QuotedText(input) : null,
                        OutputLabel = text && kind == 0 && output is not null ? QuotedText(output) : null,
                        Level = element.Level + 1, Hex = parent.Hex
                    });
                }
            }
        }

        LinkAutomationArrays(parent);

        // Associate each referenced region with its structure's pointer field and decode bounded array elements.
        var replica = inputs.Concat(outputs).FirstOrDefault(value => (value.Flags & 512) != 0);
        var structure = replica is null ? ApiMetadata.Structure(parent.SignatureType.Name) : Layout(replica);
        if (structure is null) return;
        if (parent.Children.Count == 0 && (membersBefore.Count > 0 || membersAfter.Count > 0))
            AddSnapshot(parent, null, null, structure);
        foreach (var offset in membersBefore.Concat(membersAfter).Select(value => value.MemberOffset).Distinct())
        {
            var arrayField = replica is null ? null : structure.Fields?.FirstOrDefault(value =>
                ApiMetadata.Type(value.Type)?.Kind == "Array");
            var elementLayout = arrayField is null ? structure :
                ApiMetadata.Type(ApiMetadata.Type(arrayField.Type)?.Element ?? "");
            if (elementLayout is not { Size: > 0 }) continue;
            var relative = offset - (arrayField?.Offset / 8 ?? 0);
            if (relative < 0) continue;
            var elementIndex = relative / elementLayout.Size;
            var position = relative % elementLayout.Size;
            var arrayRegion = replica is null ?
                parent.Children.FirstOrDefault(value => value.TypeName == structure.Name + "[]") :
                parent.Children.SelectMany(value => value.Children)
                    .FirstOrDefault(value => value.Name == arrayField?.Name);
            var owner = arrayRegion?.Children.FirstOrDefault(value => value.Name == $"[{elementIndex}]");
            if (owner is null && replica is null && elementIndex == 0)
                owner = parent.Children.FirstOrDefault(value => value.TypeName == structure.Name);
            var (property, field) = owner is null ? (null, null) : FindCapturedField(owner, elementLayout, position);
            if (property is null || field is null) continue;
            var before = membersBefore.FirstOrDefault(value => value.MemberOffset == offset);
            var after = membersAfter.FirstOrDefault(value => value.MemberOffset == offset);

            // Replication selectors use these flag bits for their own record types.
            if (replica is null && (((before?.Flags ?? 0) | (after?.Flags ?? 0)) & 4096) != 0)
            {
                AddNetApiSid(property, before, after);
                continue;
            }
            var pointer = ApiMetadata.Type(field.Type);
            TypeLayout? array = null;
            if (pointer is { Kind: "Pointer", Element: { } elementName } &&
                ApiMetadata.Type(elementName) is { Size: > 0 } element)
            {
                var length = Math.Max(before?.OriginalBytes ?? 0, after?.OriginalBytes ?? 0);
                array = elementName == "PctPublicKey" ? element :
                    new("Array", (int)Math.Min(length, int.MaxValue), elementName + "[]", elementName,
                    (int)Math.Min(length / (uint)element.Size, int.MaxValue));
            }

            // A record's class selector types its untyped data pointer with the layout documented for that class.
            var selected = pointer is { Kind: "Pointer", Element: "void" or "VOID" } ? owner!.Children
                .Select(value => value.Type.Choices.FirstOrDefault(choice => choice.Structures is { Length: > 0 } &&
                    choice.Value == (value.Input ?? value.Output)))
                .FirstOrDefault(choice => choice is not null)?.Structures : null;
            var extent = Math.Max(before?.OriginalBytes ?? 0, after?.OriginalBytes ?? 0);
            if (selected?.FirstOrDefault(name => ApiMetadata.Structure(name) is { } layout &&
                (ulong)layout.Size <= extent || ApiMetadata.Type(name) is
                    { Kind: "Integer" or "Boolean" or "Enum", Size: > 0 and <= 8 } scalar &&
                (ulong)scalar.Size == extent) is { } selection)
            {
                property.OverrideType = ParameterType.Infer(selection + " *");
                array = ApiMetadata.Structure(selection);
            }
            AddSnapshot(property, before, after, array);
            if (array?.Element is "char" or "CHAR" or "wchar_t" or "WCHAR")
            {
                if (before is not null && (before.Flags & 8) != 0)
                    property.Children[^1].InputLabel = QuotedText(before);
                if (after is not null && (after.Flags & 8) != 0)
                    property.Children[^1].OutputLabel = QuotedText(after);
                if ((((before?.Flags ?? 0) | (after?.Flags ?? 0)) & 8) != 0)
                    property.Children[^1].SignatureType = new(field.Type, Kind: "Pointer");
            }
        }
    }

    private static (ParameterProperty? Owner, TypeField? Field) FindCapturedField(ParameterProperty record,
        TypeLayout type, int position)
    {
        // Embedded fields retain their names while member snapshots use absolute record offsets.
        foreach (var field in type.Fields ?? [])
        {
            var child = record.Children.FirstOrDefault(value => value.Name == field.Name);
            if (child is null) continue;
            var offset = field.Offset / 8;
            if (ApiMetadata.Type(field.Type)?.Kind is "Structure" or "Union" &&
                ApiMetadata.Structure(field.Type) is { Size: > 0 } nested &&
                position >= offset && position - offset < nested.Size)
            {
                var found = FindCapturedField(child, nested, position - offset);
                if (found.Owner is not null) return found;
            }
            if (offset == position) return (child, field);
        }
        return (null, null);
    }

    private static string QuotedText(MemorySnapshot sample, bool wide = false) =>
        (sample.Flags & (uint)ValueFlags.Unreadable) != 0 ?
        "<unreadable>" : "\"" + sample.Text(wide || sample.Kind == (int)ValueKind.Utf16 ?
            Encoding.Unicode : Encoding.Latin1)
            .Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "\\0") + "\"" +
        (sample.State.Length > 0 ? " · " + sample.State : "");

    private static void AddSnapshot(ParameterProperty parent, MemorySnapshot? input, MemorySnapshot? output,
        TypeLayout? layout = null)
    {
        var sample = output ?? input;
        if (sample is { Kind: (int)ValueKind.ManagedArray })
        {
            // Runtime strides include padding; the input and output may contain different numbers of elements.
            var stride = Math.Max(sample.ElementSize, Math.Max(input?.ElementSize ?? 0, 1));
            var bytes = Math.Max(input?.OriginalBytes ?? 0, output?.OriginalBytes ?? 0);
            var runtimeElement = layout?.ElementLayout ?? new TypeLayout("Bytes", stride, $"byte[{stride}]");
            layout = new("Array", (int)Math.Min(bytes, int.MaxValue),
                layout?.Name ?? parent.TypeName.TrimEnd('&'), runtimeElement.Name,
                (int)Math.Min(bytes / (uint)stride, int.MaxValue),
                ElementLayout: runtimeElement with { Size = stride });
        }
        // Referenced string data is a separate region from the parameter's counted-string header.
        const uint ReplicaMask = (uint)(ValueFlags.LdapData | ValueFlags.ReplicaData);
        if (sample is not null && (sample.Flags & (uint)ValueFlags.ReferencedData) != 0 &&
            !((sample.Flags & ReplicaMask) == (uint)ValueFlags.ReplicaData && sample.MemberOffset < 0)) layout = null;
        else layout ??= sample is null ? null : (ValueKind)sample.Kind switch
        {
            ValueKind.FindData => ApiMetadata.Structure("WIN32_FIND_DATAW"),
            ValueKind.ProcessInformation => ApiMetadata.Structure("PROCESS_INFORMATION"),
            ValueKind.ObjectAttributes => ApiMetadata.Structure("OBJECT_ATTRIBUTES"),
            ValueKind.IoStatus => ApiMetadata.Structure("IO_STATUS_BLOCK"),
            ValueKind.Bytes => ApiMetadata.Type(parent.SignatureType.Name) is { Kind: "Array" } array ? array :
                ApiMetadata.Structure(parent.SignatureType.Name), _ => null
        };

        if (sample?.Kind == (int)ValueKind.PropertyClipboard) layout = ApiMetadata.Structure("CLIPDATA");

        // Counted pointer buffers expand only the completed extent retained in their snapshot.
        if (sample is { Kind: (int)ValueKind.Bytes } && layout?.Kind != "Array" &&
            layout?.Name is not ("SCHEDULE" or "PctPublicKey") &&
            (sample.Flags & (uint)(ValueFlags.ReferencedData | ValueFlags.ReplicaData)) == 0 &&
            ApiMetadata.Type(parent.SignatureType.Name) is { Kind: "Pointer", Element: { } arrayElement } &&
            ApiMetadata.Type(arrayElement) is { Size: > 0 } arrayType &&
            (layout is null || arrayType.Kind is "Structure" or "Union") &&
            sample.OriginalBytes > (ulong)arrayType.Size && sample.OriginalBytes % (uint)arrayType.Size == 0)
            layout = new("Array", (int)Math.Min(sample.OriginalBytes, int.MaxValue), arrayElement + "[]", arrayElement,
                (int)Math.Min(sample.OriginalBytes / (uint)arrayType.Size, int.MaxValue));
        var memory = AddCapturedNode(parent,
            parent.Children.Count == 0 ? "* value" : $"* region {parent.Children.Count + 1}",
            new(layout?.Name ?? sample?.TypeName ?? "Structure"),
            input, output);
        memory.InputLabel = input is null && output is null ? "<not captured>" : null;
        memory.OutputLabel = input is null && output is null ? "<not captured>" : null;
        if (layout is not null)
        {
            if (layout.Kind == "Array") AddArray(memory, layout, input, output, 0, 0);
            else AddFields(memory, layout, input, output);
            return;
        }
        // Scalar pointer regions retain their declared primitive types.
        var managedScalar = parent.Type.Name.EndsWith('&') &&
            Regex.IsMatch(parent.Type.Name[..^1], @"^(bool|char|u?int(8|16|32|64)|float(32|64)|n(u?int))$");
        var pointee = ApiMetadata.Type(parent.Type.Name) is { Kind: "Pointer", Element: { } element } ?
            ApiMetadata.Type(element) : null;
        var nativeScalar = pointee is { Size: > 0 and <= 8, Kind: "Integer" or "Boolean" or
            "Enum" or "Float32" or "Float64" };
        if (sample is { Bytes.Length: > 0 and <= 8 } &&
            (sample.Kind == (int)ValueKind.Scalar || sample.Kind == (int)ValueKind.Bytes &&
                (managedScalar && sample.OriginalBytes <= 8 ||
                nativeScalar && sample.OriginalBytes == (ulong)pointee!.Size)))
        {
            var declaration = parent.Type.Name.Trim();
            var type = pointee?.Name ?? Regex.Replace(declaration, @"[*&]\s*$", "").Trim();
            if (type == declaration)
            {
                if (type.StartsWith("LP")) type = type[2..];
                else if (type.StartsWith('P')) type = type[1..];
            }
            memory.Children.Add(Field(memory, "Value", ParameterType.Infer(type) with
            {
                Bits = sample.Bytes.Length * 8
            }, 0, sample.Bytes.Length));
            return;
        }
        if (sample?.Kind == (int)ValueKind.Stack)
            for (var frame = 0; frame + 8 <= sample.Bytes.Length; frame += 8)
                memory.Children.Add(Field(memory, $"#{frame / 8}", new("Pointer", Kind: "Pointer"), frame, 8));
    }

    private static void AddFields(ParameterProperty parent, TypeLayout layout,
        MemorySnapshot? input, MemorySnapshot? output, int offset = 0, int depth = 0)
    {
        if (depth >= Protocol.MaxExpansionDepth) return;

        // Decode only complete captured fields; retain field definitions when buffers are capped or unavailable.
        foreach (var field in layout.Fields ?? [])
        {
            var type = field.Layout ?? ApiMetadata.Type(field.Type);
            var position = offset + field.Offset / 8;
            if (depth == 0 && type is { Kind: "Array", Element: { } elementName } &&
                ApiMetadata.Type(elementName) is { Size: > 0 } element &&
                ((((input?.Flags ?? 0) | (output?.Flags ?? 0)) & (128 | 512)) == 512 ||
                    layout.Name == "PctPublicKey" && field.Name == "pKey"))
            {
                var extent = Math.Max(input?.OriginalBytes ?? 0, output?.OriginalBytes ?? 0);
                var count = extent >= (ulong)position ? (extent - (uint)position) / (uint)element.Size : 0;
                type = type with { Count = (int)Math.Min(count, int.MaxValue),
                    Size = (int)Math.Min(count * (uint)element.Size, int.MaxValue), Name = elementName + "[]" };
            }
            var bits = field.Bits > 0 ? field.Bits : (int)Math.Min((long)(type?.Size ?? 0) * 8, int.MaxValue);
            var bytes = (int)Math.Min(((long)field.Offset % 8 + bits + 7) / 8, int.MaxValue);
            ulong? Read(MemorySnapshot? snapshot)
            {
                if (snapshot is null || bits is < 1 or > 64 || bytes > 8 ||
                    position + bytes > snapshot.Bytes.Length) return null;
                var value = MemorySnapshot.Scalar(snapshot.Bytes, position, bytes) >> (field.Offset % 8);
                return bits == 64 ? value : value & ((1UL << bits) - 1);
            }
            var property = new ParameterProperty
            {
                Name = field.Name, SignatureType = ParameterType.Infer(type?.Kind == "Array" ?
                    type.Name ?? field.Type : field.Type), Level = parent.Level + 1,
                Hex = parent.Hex, Input = Read(input), Output = Read(output)
            };
            if (type?.Kind is "Structure" or "Union" or "Array")
            {
                property.Input = property.Output = null;
                property.InputMemory = Slice(input, position, type.Size);
                property.OutputMemory = Slice(output, position, type.Size);
                if (type.Kind == "Array") AddArray(property, type, input, output, position, depth + 1);
                else AddFields(property, type, input, output, position, depth + 1);
            }
            else if (field.Bits > 0) property.SignatureType = property.SignatureType with { Bits = field.Bits };
            if (property.Input is null && property.InputMemory is null)
                property.InputLabel = Missing(input, position, bytes);
            if (property.Output is null && property.OutputMemory is null)
                property.OutputLabel = Missing(output, position, bytes);
            parent.Children.Add(property);
        }

        // Schedule offsets select bytes already present in the captured variable-size allocation.
        if (depth != 0 || layout.Name != "SCHEDULE") return;
        var sample = output ?? input;
        if (sample is null || sample.Bytes.Length < 20 || MemorySnapshot.Scalar(sample.Bytes, 8, 4) != 1) return;
        var dataOffset = MemorySnapshot.Scalar(sample.Bytes, 16, 4);
        if (dataOffset < 20 || dataOffset > int.MaxValue || dataOffset >= sample.OriginalBytes) return;
        var dataSize = (int)Math.Min(sample.OriginalBytes - dataOffset, int.MaxValue);
        var data = AddCapturedNode(parent, "Schedule data [0]", new("byte[]"),
            Slice(input, (int)dataOffset, dataSize), Slice(output, (int)dataOffset, dataSize));
        data.InputLabel = input is null || dataOffset >= (ulong)input.Bytes.Length ? "<not captured>" : null;
        data.OutputLabel = output is null || dataOffset >= (ulong)output.Bytes.Length ? "<not captured>" : null;

        // MS-ADTS interval schedules give each GMT hour one byte whose 0x8, 0x4, 0x2 and 0x1 bits are its quarters.
        if (MemorySnapshot.Scalar(sample.Bytes, 12, 4) != 0) return;
        static string? Intervals(MemorySnapshot? hours)
        {
            if (hours is not { Bytes.Length: 24 }) return null;
            var ranges = new List<string>();
            for (int quarter = 0, start = -1; quarter <= 96; ++quarter)
            {
                var allowed = quarter < 96 && (hours.Bytes[quarter / 4] & (0x8 >> quarter % 4)) != 0;
                if (allowed && start < 0) start = quarter;
                if (allowed || start < 0) continue;
                ranges.Add($"{start / 4:00}:{start % 4 * 15:00}–{quarter / 4:00}:{quarter % 4 * 15:00}");
                start = -1;
            }
            return ranges.Count == 0 ? "No replication" : string.Join(", ", ranges);
        }
        string[] days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
        for (var day = 0; day < days.Length && (day + 1) * 24 <= dataSize; ++day)
        {
            var before = Slice(data.InputMemory, day * 24, 24);
            var after = Slice(data.OutputMemory, day * 24, 24);
            data.Children.Add(new()
            {
                Name = days[day] + " (GMT)", SignatureType = new("byte[24]"), Level = data.Level + 1, Hex = parent.Hex,
                InputMemory = before, OutputMemory = after, InputLabel = Intervals(before) ?? Missing(before, 0, 24),
                OutputLabel = Intervals(after) ?? Missing(after, 0, 24)
            });
        }
    }

    private static string Missing(MemorySnapshot? snapshot, int offset, int size)
    {
        if (snapshot is null) return "<not captured>";
        if ((snapshot.Flags & (uint)ValueFlags.Unreadable) != 0) return "<unreadable>";
        if ((snapshot.Flags & (uint)ValueFlags.Pending) != 0) return "<pending>";
        var available = Math.Clamp(snapshot.Bytes.Length - offset, 0, size);
        return available == 0 ? "<not captured>" : $"<partial: {available} / {size} bytes>";
    }

    private static MemorySnapshot? Slice(MemorySnapshot? snapshot, int offset, int size)
    {
        if (snapshot is null || offset >= snapshot.Bytes.Length) return null;
        var count = Math.Min(size, snapshot.Bytes.Length - offset);
        return new((int)ValueKind.Bytes, snapshot.Flags | (count < size ? (uint)ValueFlags.Truncated : 0u),
            (ulong)size, snapshot.Bytes.AsSpan(offset, count).ToArray());
    }

    private static void AddArray(ParameterProperty parent, TypeLayout layout,
        MemorySnapshot? input, MemorySnapshot? output, int offset, int depth)
    {
        if (depth >= Protocol.MaxExpansionDepth) return;
        if (layout.Element is null) return;
        var element = layout.ElementLayout ?? ApiMetadata.Type(layout.Element);
        if (element is not { Size: > 0 }) return;
        if (layout.Element is "WCHAR" or "wchar_t" or "CHAR" or "char")
        {
            string? Text(MemorySnapshot? snapshot)
            {
                if (snapshot is null || offset >= snapshot.Bytes.Length) return null;
                var length = Math.Min(layout.Size, snapshot.Bytes.Length - offset);
                if (element.Size == 2) length &= ~1;
                var value = (element.Size == 2 ? Encoding.Unicode : Encoding.Latin1)
                    .GetString(snapshot.Bytes, offset, length);
                var end = value.IndexOf('\0');
                return "\"" + (end < 0 ? value : value[..end]) + "\"" +
                    (end < 0 && length < layout.Size ? " · truncated" : "");
            }
            parent.InputLabel = Text(input);
            parent.OutputLabel = Text(output);
            return;
        }

        // Bound the visible array expansion independently of the captured buffer's configured size.
        var available = Math.Max(input?.Bytes.Length ?? 0, output?.Bytes.Length ?? 0) - offset;
        var count = Math.Min(layout.Count, Math.Min(Protocol.MaxExpandedElements,
            Math.Max(1, (available + element.Size - 1) / element.Size)));
        for (var index = 0; index < count; ++index)
        {
            var value = new ParameterProperty
            {
                Name = $"[{index}]", SignatureType = ParameterType.Infer(layout.Element), Level = parent.Level + 1,
                Hex = parent.Hex, InputMemory = Slice(input, offset + index * element.Size, element.Size),
                OutputMemory = Slice(output, offset + index * element.Size, element.Size)
            };
            if (element.Kind is "Structure" or "Union")
                AddFields(value, element, input, output, offset + index * element.Size, depth);
            else if (element.Kind == "Array")
                AddArray(value, element, input, output, offset + index * element.Size, depth + 1);
            else if (element.Kind != "Bytes")
            {
                value.Input = value.InputMemory is { } before &&
                    before.Bytes.Length == element.Size && element.Size <= 8 ?
                    MemorySnapshot.Scalar(before.Bytes, 0, element.Size) : null;
                value.Output = value.OutputMemory is { } after &&
                    after.Bytes.Length == element.Size && element.Size <= 8 ?
                    MemorySnapshot.Scalar(after.Bytes, 0, element.Size) : null;
            }
            value.InputLabel = value.InputMemory is null ? "<not captured>" : null;
            value.OutputLabel = value.OutputMemory is null ? "<not captured>" : null;
            parent.Children.Add(value);
        }
        if (layout.Count > count)
            parent.Children.Add(new()
            {
                Name = $"[{count}…{layout.Count - 1}]", SignatureType = ParameterType.Infer(layout.Element),
                Level = parent.Level + 1, InputLabel = $"{layout.Count - count:N0} more elements",
                OutputLabel = $"{layout.Count - count:N0} more elements"
            });
    }

    private static ParameterProperty Field(ParameterProperty parent, string name,
        ParameterType type, int offset, int size) => new()
    {
        Name = name, SignatureType = type, Level = parent.Level + 1, Hex = parent.Hex,
        Input = parent.InputMemory is { } input && offset + size <= input.Bytes.Length ?
            MemorySnapshot.Scalar(input.Bytes, offset, size) : null,
        Output = parent.OutputMemory is { } output && offset + size <= output.Bytes.Length ?
            MemorySnapshot.Scalar(output.Bytes, offset, size) : null
    };


    private static readonly Dictionary<(int Width, int Selector), TypeLayout?> replicaLayouts = [];
    private static long replicaRevision = -1;

    private static TypeLayout? ReplicaLayout(int selector)
    {
        // Resolve each selector once for the active catalog revision and pointer size.
        lock (replicaLayouts)
        {
            if (replicaRevision != ApiMetadata.Revision)
            {
                replicaLayouts.Clear();
                replicaRevision = ApiMetadata.Revision;
            }
            var key = (ApiMetadata.PointerSize, selector);
            if (!replicaLayouts.TryGetValue(key, out var layout))
            {
                var structure = "";
                foreach (var choice in ApiMetadata.Type("DS_REPL_INFO_TYPE")?.Choices ?? [])
                    if (choice.Value == (ulong)selector)
                    {
                        structure = choice.Structures?.FirstOrDefault() ?? "";
                        break;
                    }
                layout = ApiMetadata.Structure(structure);
                replicaLayouts[key] = layout;
            }
            return layout;
        }
    }

    private static ParameterProperty AddCapturedNode(ParameterProperty parent, string name, ParameterType type,
        MemorySnapshot? before, MemorySnapshot? after, bool? hex = null)
    {
        var record = new ParameterProperty
        {
            Name = name, SignatureType = type, InputMemory = before, OutputMemory = after,
            Level = parent.Level + 1, Hex = hex ?? parent.Hex
        };
        parent.Children.Add(record);
        return record;
    }

    private static ParameterProperty AddCapturedRecord(ParameterProperty parent, string name, string type,
        MemorySnapshot? before, MemorySnapshot? after, TypeLayout? layout, string kind = "Structure")
    {
        // Catalog structures and arrays share the same recorded-memory expansion.
        var record = AddCapturedNode(parent, name, new(type, Kind: kind), before, after);
        if (layout?.Kind == "Array") AddArray(record, layout, before, after, 0, 0);
        else if (layout is not null) AddFields(record, layout, before, after);
        return record;
    }

    private static void AddCapturedReference(ParameterProperty parent, string name, ParameterType type,
        MemorySnapshot? before, MemorySnapshot? after, bool text = false)
    {
        // Referenced regions retain independent input and output states.
        if (before is null && after is null) return;
        var reference = AddCapturedNode(parent, name, type, before, after);
        reference.InputLabel = text && before is not null ? QuotedText(before) : null;
        reference.OutputLabel = text && after is not null ? QuotedText(after) : null;
    }
}
