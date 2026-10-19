using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media.Imaging;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static ParameterProperty NetApiField(ParameterProperty array, TypeLayout layout, int offset)
    {
        var record = array.Children.Single(value => value.Name == $"[{offset / layout.Size}]");
        var field = layout.Fields!.Single(value => value.Offset == offset % layout.Size * 8);
        return record.Children.Single(value => value.Name == field.Name);
    }

    private static void InspectBufferElements(JsonDocument details)
    {
        // Expand real collector details, preserving referenced regions and their owning array elements.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var family = item.Text("family");
            var call = item.GetProperty("call");
            var parameter = (int)item.Number("parameter", 3);
            var row = ParameterValues.Build(call).Single(value => value.Parameter == parameter);
            var storedParameter = parameter < 0 ? uint.MaxValue : (uint)parameter;
            var snapshots = call.Items("input").Where(value => value.Number("parameter") == storedParameter)
                .Select(MemorySnapshot.FromJson).ToArray();
            var returned = call.Items("output").Where(value => value.Number("parameter") == storedParameter)
                .Select(MemorySnapshot.FromJson).ToArray();
            (MemorySnapshot Capture, TypeLayout Layout, ParameterProperty Array) NetApiRecords()
            {
                var capture = returned.Single(value => value.Structure.Length > 0 && value.MemberOffset < 0);
                return (capture, ApiMetadata.Structure(capture.Structure)!,
                    row.Children.Single(value => value.Name == "Records"));
            }

            var nodes = Flatten([row]);
            if (family == "restore")
            {
                var structure = ApiMetadata.Structure(row.SignatureType.Name)!;
                var array = row.Children.Single(value => value.TypeName == structure.Name + "[]");
                foreach (var snapshot in snapshots.Where(value => value.MemberOffset >= 0))
                {
                    var element = snapshot.MemberOffset / structure.Size;
                    var field = structure.Fields!.Single(value =>
                        value.Offset == snapshot.MemberOffset % structure.Size * 8);
                    var owner = array.Children.Single(value => value.Name == $"[{element}]");
                    var text = owner.Children.Single(value => value.Name == field.Name).Children.Single();
                    Require(text.InputMemory?.Bytes.SequenceEqual(snapshot.Bytes) == true &&
                        text.TypeName != "BSTR" && text.InputText.StartsWith('"'),
                        "A restoration-map string lost its owning structure element or presumed text type.");
                }
                var second = array.Children.FirstOrDefault(value => value.Name == "[1]");
                if (item.Number("limit") < 32 && second is not null)
                    Require(second.Children.All(value => value.Children.Count == 0),
                        "A partial restoration-map descriptor fabricated referenced strings.");
            }
            else if (family == "dbgeng")
            {
                var types = item.Items("types").Select(value => value.GetString()).ToArray();
                var first = (int)item.Number("first");
                var fields = parameter < 0 ? ParameterValues.Build(call)
                    .Where(value => value.Parameter >= first).ToArray() :
                    row.Children.Where(value => value.InputMemory is { Kind: 2 } memory &&
                        (memory.Flags & 64) != 0).OrderBy(value => value.InputMemory!.ElementIndex).ToArray();
                Require(fields.Length == types.Length && fields.Select(value => value.TypeName)
                    .SequenceEqual(types), "Debugger output lost its presumed variable argument types.");
                Require(fields.All(value => !value.Name.StartsWith("Argument [", StringComparison.Ordinal)),
                    "Debugger output list arguments lost their format roles.");
                foreach (var field in fields.Where(value => value.TypeName is "char *" or "wchar_t *"))
                    Require(field.Children.Count == 1 && field.Children[0].InputText.StartsWith('"'),
                        $"Debugger output text: {call.Text("name")}, {field.Name}: " +
                        string.Join(", ", field.Children.Select(value => value.InputText)));
            }
            else if (family == "positional")
            {
                var scalars = snapshots.Where(value => (value.Flags & 64) != 0 && value.Kind == 2).ToArray();
                var groups = row.Children.Where(value => value.InputMemory is { Kind: 2 } memory &&
                    (memory.Flags & 64) != 0).ToArray();
                Require(groups.Length == scalars.Length && groups.All(value =>
                    !value.Name.StartsWith("Argument [", StringComparison.Ordinal)),
                    "A positional formatter lost its named argument slots.");
                foreach (var scalar in scalars)
                {
                    var group = groups.Single(value => value.InputMemory!.ElementIndex == scalar.ElementIndex);
                    Require(group.Input == MemorySnapshot.Scalar(scalar.Bytes, 0, 8),
                        "A positional formatter changed a captured argument value.");
                    foreach (var reference in snapshots.Where(value => value.ElementIndex == scalar.ElementIndex &&
                        value.Kind is 0 or 1 && (value.Flags & 8) != 0))
                        Require(group.Children.Single().InputMemory?.Bytes.SequenceEqual(reference.Bytes) == true &&
                            group.TypeName == (reference.Kind == 1 ? "wchar_t *" : "char *"),
                            "A positional string lost its owning argument or character type.");
                }
            }
            else if (family == "ucrt")
            {
                var rawWindow = snapshots.FirstOrDefault(value => value.Kind == 0 && (value.Flags & 64) == 0);
                if (rawWindow is not null)
                    Require(row.Children.Any(value => value.TypeName == "Raw argument window" &&
                        value.InputMemory?.Bytes.SequenceEqual(rawWindow.Bytes) == true &&
                        value.Children.Count == 0),
                        "The va_list byte window was interpreted as a character array.");
                var scalars = snapshots.Where(value => (value.Flags & 64) != 0 && value.Kind == 2).ToArray();
                var groups = row.Children.Where(value => value.InputMemory is { Kind: 2 } memory &&
                    (memory.Flags & 64) != 0).ToArray();
                Require(groups.Length == scalars.Length && scalars.Length == 7,
                    "The va_list inspector lost a captured scalar argument.");
                foreach (var scalar in scalars)
                {
                    var group = groups.Single(value => value.InputMemory!.ElementIndex == scalar.ElementIndex);
                    Require(group.Input == MemorySnapshot.Scalar(scalar.Bytes, 0, 8),
                        "A va_list argument changed its captured register-width bits.");
                    var references = snapshots.Where(value => value.ElementIndex == scalar.ElementIndex &&
                        value.Kind is 0 or 1 && (value.Flags & 8) != 0).ToArray();
                    Require(group.Children.Count == references.Length,
                        "The va_list inspector discarded text behind its scalar pointer snapshot.");
                    foreach (var reference in references)
                    {
                        var text = group.Children.Single(value => value.InputMemory?.Kind == reference.Kind);
                        Require(text.InputMemory!.Bytes.SequenceEqual(reference.Bytes) &&
                            text.TypeName == (reference.Kind == 1 ? "wchar_t *" : "char *"),
                            "A va_list string lost its bytes or used a BSTR type without a counted contract.");
                        if (!group.Name.StartsWith("Argument [", StringComparison.Ordinal))
                            Require(group.TypeName == (reference.Kind == 1 ? "wchar_t *" : "char *"),
                                "A complete UCRT format lost its option-specific argument type.");
                    }
                }
            }
            else if (family == "ldap")
            {
                var table = row.Children.Single(value => value.Name == "Modification pointers");
                Require(row.Children.Count == 1,
                    "A duplicate unpopulated LDAP structure was added beside the modification array.");
                var descriptors = snapshots.Where(value => value.LdapPart == 1).ToArray();
                Require(table.Children.Count == descriptors.Length,
                    "LDAP descriptors were combined or detached from their modification indexes.");
                foreach (var descriptor in descriptors)
                {
                    var modification = table.Children.Single(value => value.Name == $"[{descriptor.ModIndex}]");
                    Require(modification.Children.Single(value => value.Name == "mod_op").Input ==
                        (descriptor.Bytes.Length >= 4 ? MemorySnapshot.Scalar(descriptor.Bytes, 0, 4) : null) &&
                        modification.Children.Any(value => value.Name == "mod_type") &&
                        modification.Children.Any(value => value.Name == "mod_vals"),
                        "The LDAP modification lost its named SDK fields.");
                }
                foreach (var snapshot in snapshots.Where(value => value.LdapPart is 2 or 4 or 6))
                    Require(nodes.Any(value => value.InputMemory is { } memory &&
                        memory.ModIndex == snapshot.ModIndex && memory.LdapPart == snapshot.LdapPart &&
                        memory.ElementIndex == snapshot.ElementIndex && memory.Bytes.SequenceEqual(snapshot.Bytes)),
                        "An LDAP attribute, string value or counted BERVAL payload was omitted.");
                foreach (var binary in snapshots.Where(value => value.LdapPart == 5))
                    Require(nodes.Any(value => value.TypeName == "BERVAL" &&
                        value.InputMemory?.ModIndex == binary.ModIndex &&
                        value.InputMemory?.ElementIndex == binary.ElementIndex &&
                        value.Children.Any(field => field.Name == "bv_len") &&
                        value.Children.Any(field => field.Name == "bv_val")),
                        "A binary LDAP value lost its expandable BERVAL length or pointer.");
            }
            else if (family is "ldap-control" or "ldap-berval" or "ldap-ber-values")
            {
                Require(!row.Children.Any(value => value.Name == "Modification pointers"),
                    "LDAP controls or cookies were expanded as modification arrays.");
                var samples = snapshots.Concat(returned).Where(value => (value.Flags & 128) != 0).ToArray();
                if (family == "ldap-ber-values")
                {
                    var table = row.Children.Single(value => value.Name == "Values");
                    Require(table.TypeName == "BERVAL *[]" && table.Children.Count ==
                        samples.Where(value => value.LdapPart == 5).Select(value => value.ModIndex).Distinct().Count(),
                        "A returned LDAP vector lost its binary value indexes.");
                }
                foreach (var descriptor in samples.Where(value => value.LdapPart is 5 or 7))
                {
                    var region = nodes.Single(value =>
                        value.InputMemory is { } before && before.LdapPart == descriptor.LdapPart &&
                            before.ModIndex == descriptor.ModIndex ||
                        value.OutputMemory is { } after && after.LdapPart == descriptor.LdapPart &&
                            after.ModIndex == descriptor.ModIndex);
                    var fields = descriptor.LdapPart == 7 ?
                        new[] { "ldctl_oid", "ldctl_value", "ldctl_iscritical" } : new[] { "bv_len", "bv_val" };
                    Require(fields.All(field => region.Children.Any(value => value.Name == field)),
                        "A captured LDAP descriptor lost named fields.");
                    var related = samples.Where(value => value.ModIndex == descriptor.ModIndex &&
                        value.LdapPart == (descriptor.LdapPart == 7 ? 9 : 6)).ToArray();
                    var pointer = descriptor.LdapPart == 7 ?
                        region.Children.Single(value => value.Name == "ldctl_value").Children
                            .Single(value => value.Name == "bv_val") :
                        region.Children.Single(value => value.Name == "bv_val");
                    foreach (var data in related)
                        Require(pointer.Children.Any(value =>
                            value.InputMemory?.Bytes.SequenceEqual(data.Bytes) == true ||
                            value.OutputMemory?.Bytes.SequenceEqual(data.Bytes) == true),
                            "An LDAP binary value lost its owning descriptor field.");
                    if (descriptor.LdapPart != 7) continue;
                    var oid = region.Children.Single(value => value.Name == "ldctl_oid");
                    foreach (var text in samples.Where(value => value.ModIndex == descriptor.ModIndex &&
                        value.LdapPart == 8))
                        Require(oid.Children.Any(value => value.InputMemory?.Bytes.SequenceEqual(text.Bytes) == true ||
                            value.OutputMemory?.Bytes.SequenceEqual(text.Bytes) == true),
                            "An LDAP control OID lost its owning field.");
                }
            }
            else if (family == "etw")
            {
                if (item.TryGetProperty("traceMessage", out var traceMessage) && traceMessage.ValueKind ==
                    JsonValueKind.True)
                {
                    var capture = snapshots.Single(value => value.EtwFormat == 5);
                    var table = row.Children.Single(value => value.Name == "Argument pairs");
                    Require(table.InputMemory?.Bytes.SequenceEqual(capture.Bytes) == true &&
                        table.Children.Count(value => value.Name.StartsWith('[')) <= 128,
                        "A TraceMessage argument table lost its bytes or exceeded the display limit.");
                    foreach (var pair in table.Children.Where(value => value.Name.StartsWith('[')))
                    {
                        var index = int.Parse(pair.Name.AsSpan(1, pair.Name.Length - 2));
                        var offset = index * 16;
                        foreach (var (name, position) in new[] { ("Pointer", 0), ("Length", 8) })
                            Require(pair.Children.Single(value => value.Name == name).Input ==
                                (capture.Bytes.Length >= offset + position + 8 ?
                                    MemorySnapshot.Scalar(capture.Bytes, offset + position, 8) : (ulong?)null),
                                "A TraceMessage pair lost its declared pointer or size.");
                        foreach (var reference in snapshots.Where(value => value.EtwFormat == 6 &&
                            value.MemberOffset == offset))
                            Require(pair.Children.Single(value => value.Name == "Pointer").Children
                                .Any(value => value.InputMemory?.Bytes.SequenceEqual(reference.Bytes) == true),
                                "A TraceMessage payload lost its owning argument pair.");
                    }
                    continue;
                }
                foreach (var capture in snapshots.Concat(returned).Where(value => value.EtwFormat >= 0 &&
                    value.MemberOffset < 0))
                {
                    var type = capture.EtwFormat switch
                    {
                        0 => "EVENT_DATA_DESCRIPTOR", 1 => "EVENT_TRACE_HEADER",
                        2 => "EVENT_INSTANCE_HEADER", 3 => "MOF_FIELD", _ => ""
                    };
                    var layout = ApiMetadata.Structure(type)!;
                    var region = row.Children.Single(value => value.TypeName == type +
                        (capture.EtwFormat is 0 or 3 ? "[]" : ""));
                    Require(region.InputMemory?.Bytes.SequenceEqual(capture.Bytes) == true ||
                        region.OutputMemory?.Bytes.SequenceEqual(capture.Bytes) == true,
                        "An ETW buffer lost its recorded descriptor or header bytes.");
                    if (capture.EtwFormat is 1 or 2)
                    {
                        Require(layout.Fields!.All(field => region.Children.Any(value => value.Name == field.Name)),
                            "A classic ETW header lost its named SDK fields.");
                        var fields = Flatten([region]);
                        foreach (var (name, offset, bytes) in new[]
                            { ("ThreadId", 8, 4), ("ProcessId", 12, 4), ("Flags", 44, 4) })
                            Require(fields.Single(value => value.Name == name).Input ==
                                (capture.Bytes.Length >= offset + bytes ?
                                    MemorySnapshot.Scalar(capture.Bytes, offset, bytes) : (ulong?)null),
                                "A classic ETW field lost its independent SDK offset or captured value.");
                        if (capture.EtwFormat == 2)
                        {
                            Require(fields.All(value => value.Name != "GuidPtr") &&
                                fields.Single(value => value.Name == "RegHandle").Input ==
                                (capture.Bytes.Length >= 32 ?
                                    MemorySnapshot.Scalar(capture.Bytes, 24, 8) : (ulong?)null),
                                "An instance event interpreted its registration handle as a GUID pointer.");
                            continue;
                        }
                        var pointer = fields.Single(value => value.Name == "GuidPtr");
                        Require(pointer.Input == (capture.Bytes.Length >= 32 ?
                            MemorySnapshot.Scalar(capture.Bytes, 24, 8) : (ulong?)null),
                            "A classic ETW GUID pointer lost its independent SDK offset.");
                        foreach (var reference in snapshots.Concat(returned).Where(value =>
                            value.EtwFormat == 4 && value.MemberOffset == 24))
                        {
                            var guid = pointer.Children.Single(value => value.TypeName == "GUID");
                            Require(guid.InputMemory?.Bytes.SequenceEqual(reference.Bytes) == true ||
                                guid.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true,
                                "A referenced ETW GUID lost its owning header pointer.");
                            Require(guid.Children.Single(value => value.Name == "Data1").Input ==
                                (reference.Bytes.Length >= 4 ?
                                    MemorySnapshot.Scalar(reference.Bytes, 0, 4) : (ulong?)null),
                                "A referenced ETW GUID lost its named fields or captured bytes.");
                        }
                        continue;
                    }
                    Require(region.Children.Count(value => value.Name.StartsWith('[')) <= 128,
                        "An ETW descriptor array exceeded the property grid expansion limit.");
                    foreach (var reference in snapshots.Concat(returned).Where(value =>
                        value.EtwFormat == capture.EtwFormat && value.MemberOffset >= 0))
                    {
                        var record = region.Children.Single(value => value.Name ==
                            $"[{reference.MemberOffset / layout.Size}]");
                        var pointer = record.Children.Single(value => value.Name ==
                            (capture.EtwFormat == 0 ? "Ptr" : "DataPtr"));
                        Require(pointer.Children.Any(value =>
                            value.InputMemory?.Bytes.SequenceEqual(reference.Bytes) == true ||
                            value.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true),
                            "An ETW payload lost its owning descriptor pointer.");
                    }
                }
            }
            else if (family == "oid")
            {
                // Object identifier arcs expand as integers beneath the packed structure's pointer field.
                var before = snapshots.SingleOrDefault(value => value.MemberOffset == 4);
                var after = returned.SingleOrDefault(value => value.MemberOffset == 4);
                var array = nodes.Single(value => value.Name == "ids").Children.Single();
                Require(array.TypeName == "UINT[]" && (before ?? after) is not null &&
                    (before is null ? array.InputMemory is null :
                        array.InputMemory?.Bytes.SequenceEqual(before.Bytes) == true) &&
                    (after is null ? array.OutputMemory is null :
                        array.OutputMemory?.Bytes.SequenceEqual(after.Bytes) == true),
                    "Object identifier arcs lost their owning pointer field.");
                foreach (var (memory, input) in new[] { (before, true), (after, false) })
                {
                    if (memory is null) continue;
                    var arcs = array.Children.Select(value => input ? value.Input : value.Output).ToArray();
                    var captured = memory.Bytes.Length / 4;
                    Require(arcs.Length >= captured && arcs.Skip(captured).All(value => value is null) &&
                        Enumerable.Range(0, captured).All(index =>
                            arcs[index] == MemorySnapshot.Scalar(memory.Bytes, index * 4, 4)),
                        "An object identifier arc lost its integer value or exceeded its captured bytes.");
                }
            }
            else if (family == "netapi-bytes")
            {
                if (!returned.Any(value => value.Structure.Length > 0 && value.MemberOffset < 0))
                {
                    Require(!row.Children.Any(value => value.Name == "Records"),
                        "A failed NetAPI call fabricated an output record array.");
                    continue;
                }
                var (_, layout, array) = NetApiRecords();
                foreach (var reference in returned.Where(value => value.Buffer))
                {
                    var bytes = NetApiField(array, layout, reference.MemberOffset).Children.Single();
                    Require(bytes.Name == "Bytes" && bytes.TypeName == "byte[]" &&
                        bytes.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true &&
                        !bytes.OutputText.StartsWith('"'),
                        "A NetAPI byte buffer lost its owning SDK field or was interpreted as text.");
                }
            }
            else if (family == "netapi-security")
            {
                var (_, layout, array) = NetApiRecords();
                foreach (var header in returned.Where(value => value.SecurityPart == 0))
                {
                    var descriptor = NetApiField(array, layout, header.MemberOffset).Children.Single();
                    var type = header.OriginalBytes == 20 || header.Bytes.Length >= 4 &&
                        (MemorySnapshot.Scalar(header.Bytes, 2, 2) & 0x8000) != 0 ?
                        "SECURITY_DESCRIPTOR_RELATIVE" : "SECURITY_DESCRIPTOR";
                    Require(descriptor.TypeName == type &&
                        descriptor.OutputMemory?.Bytes.SequenceEqual(header.Bytes) == true &&
                        descriptor.Children.Any(value => value.Name == "Control"),
                        "A share security descriptor lost its SDK representation or captured header.");
                    foreach (var part in returned.Where(value => value.MemberOffset == header.MemberOffset &&
                        value.SecurityPart > 0))
                    {
                        var name = part.SecurityPart switch
                        {
                            1 => "Owner", 2 => "Group", 3 => "Dacl", _ => "Sacl"
                        };
                        var owner = descriptor.Children.Single(value => value.Name == name);
                        var component = owner.Children.Single();
                        Require(component.TypeName == (part.SecurityPart <= 2 ? "SID" : "ACL") &&
                            component.OutputMemory?.Bytes.SequenceEqual(part.Bytes) == true,
                            "A descriptor component lost its owning field, SDK type or recorded bytes.");
                        if (part.SecurityPart <= 2) continue;
                        foreach (var entry in component.Children.Where(value =>
                            value.Name.StartsWith("ACE [")))
                        {
                            Require(entry.OutputMemory is { Bytes.Length: >= 4 } memory &&
                                entry.Children.Single(value => value.Name == "AceType").Output ==
                                    memory.Bytes[0] &&
                                entry.Children.Single(value => value.Name == "AceSize").Output ==
                                    MemorySnapshot.Scalar(memory.Bytes, 2, 2),
                                "An ACL entry lost its recorded ACE header fields.");
                            var sid = entry.Children.FirstOrDefault(value => value.TypeName == "SID");
                            if (sid?.OutputMemory is not { Bytes.Length: >= 8 } bytes) continue;
                            Require(bytes.Bytes[0] == 1 && bytes.Bytes[1] <= 15 &&
                                sid.Children.Any(value => value.Name == "SubAuthority"),
                                "A basic ACE lost its validated inline SID.");
                        }

                        // Windows' SDDL rendering supplies object GUIDs, conditions and resource attributes.
                        var recordIndex = header.MemberOffset / layout.Size;
                        if (!item.TryGetProperty("sddl", out var renderings) ||
                            renderings.ValueKind != JsonValueKind.Array ||
                            recordIndex >= renderings.GetArrayLength() ||
                            renderings[recordIndex].GetString() is not { } rendering) continue;
                        var expected = SddlAces(rendering, part.SecurityPart == 3 ? 'D' : 'S');
                        var entries = component.Children.Where(value => value.Name.StartsWith("ACE [")).ToList();
                        Require(entries.Count <= expected.Count && (part.Bytes.Length < (int)part.OriginalBytes ||
                            entries.Count == expected.Count),
                            "A captured ACL lost or fabricated entries compared with its Windows rendering.");
                        for (var position = 0; position < entries.Count; ++position)
                        {
                            var entry = entries[position];
                            if (entry.OutputMemory is not { } memory ||
                                (ulong)memory.Bytes.Length < memory.OriginalBytes) continue;
                            var fields = expected[position];
                            string? Label(string name) =>
                                entry.Children.FirstOrDefault(value => value.Name == name)?.OutputLabel;
                            static string? Field(string[] fields, int index) =>
                                index < fields.Length && fields[index].Length > 0 ? fields[index] : null;
                            Require(entry.Children.Any(value => value.Name == "Mask") &&
                                entry.Children.Any(value => value.TypeName == "SID"),
                                "A complete ACE lost its access mask or trustee SID.");
                            Require(Label("ObjectType")?.Trim('{', '}') == Field(fields, 3) &&
                                Label("InheritedObjectType")?.Trim('{', '}') == Field(fields, 4),
                                "An object ACE GUID differs from its Windows rendering.");
                            Require((Label("ApplicationData") ?? Label("AttributeData")) == Field(fields, 6),
                                "A conditional or resource-attribute ACE body differs from its Windows rendering.");
                        }
                    }
                }
            }
            else if (family == "netapi-sid")
            {
                var (_, layout, array) = NetApiRecords();
                foreach (var reference in returned.Where(value => value.Sid))
                {
                    var sid = NetApiField(array, layout, reference.MemberOffset).Children
                        .Single(value => value.TypeName == "SID");
                    Require(sid.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true &&
                        sid.Children.Any(value => value.Name == "Revision") &&
                        sid.Children.Any(value => value.Name == "SubAuthorityCount") &&
                        sid.Children.Any(value => value.Name == "IdentifierAuthority"),
                        "A NetAPI SID lost its owning field, bytes or fixed authority fields.");
                    var valid = reference.Bytes.Length >= 8 && reference.Bytes[0] == 1 &&
                        reference.Bytes[1] <= 15;
                    var subAuthorities = sid.Children.Single(value => value.Name == "SubAuthority");
                    Require(valid || subAuthorities.Children.Count == 0,
                        "An invalid SID header fabricated variable subauthority fields.");
                    if (valid && reference.Bytes.Length >= 8 + reference.Bytes[1] * 4)
                    {
                        Require(sid.OutputText.StartsWith("S-1-"),
                            "A complete NetAPI SID lost its standard string representation.");
                        if (reference.Bytes.AsSpan(2, 6).SequenceEqual(
                            new byte[] {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56}))
                            Require(sid.OutputText.StartsWith("S-1-0xABCDEF123456-"),
                                "A SID identifier authority lost its Windows hexadecimal representation.");
                        Require(subAuthorities.Children.Count == reference.Bytes[1],
                            "A complete SID lost its declared variable subauthority count.");
                        for (var index = 0; index < reference.Bytes[1]; ++index)
                            Require(subAuthorities.Children[index].Output ==
                                MemorySnapshot.Scalar(reference.Bytes, 8 + index * 4, 4),
                                "A SID subauthority value was decoded from the wrong bytes.");
                    }
                }
            }
            else if (family == "netapi-getter")
            {
                var capture = returned.SingleOrDefault(value => value.Structure.Length > 0 && value.MemberOffset < 0);
                if (capture is null)
                {
                    Require(!row.Children.Any(value => value.Name == "Records"),
                        "A failed getter fabricated a returned SDK record.");
                    continue;
                }
                var layout = ApiMetadata.Structure(capture.Structure)!;
                var array = row.Children.Single(value => value.Name == "Records");
                Require(capture.OriginalBytes == (uint)layout.Size &&
                    array.Children.Count(value => value.Name.StartsWith('[')) <= 1,
                    "A NetAPI getter interpreted its allocation as multiple records.");
                foreach (var reference in returned.Where(value => value.MemberOffset >= 0 &&
                    value.Structure.Length > 0))
                {
                    var record = array.Children.Single(value => value.Name == "[0]");
                    var fields = Flatten([record]);
                    var position = reference.MemberOffset;
                    var name = capture.Structure.StartsWith("USE_INFO_") ? position switch
                    {
                        0 => "ui2_local", 8 => "ui2_remote", 16 => "ui2_password", 40 => "ui2_username",
                        48 => "ui2_domainname", 72 => "ui4_auth_identity", 88 => "ui5_security_descriptor",
                        104 => "ui5_use_options", _ => throw new InvalidOperationException("Unknown use member")
                    } : layout.Fields!.Single(value => value.Offset == position * 8).Name;
                    if (capture.Structure is "USE_INFO_0" or "USE_INFO_1")
                        name = layout.Fields!.Single(value => value.Offset == position * 8).Name;
                    var owner = fields.Single(value => value.Name == name);
                    Require(owner.Output == MemorySnapshot.Scalar(capture.Bytes, reference.MemberOffset, 8) &&
                        owner.Children.Any(value =>
                        value.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true),
                        "A getter reference lost its named SDK field or captured bytes.");
                    Require(!reference.Buffer || owner.Children.Single().TypeName == "byte[]",
                        "A counted getter blob was interpreted as text.");
                    Require(!reference.Sid || owner.Children.Any(value => value.TypeName == "SID"),
                        "A getter SID lost its expandable structure.");
                }
            }
            else if (family == "netapi")
            {
                var (capture, layout, array) = NetApiRecords();
                Require(array.TypeName == capture.Structure + "[]" &&
                    array.Children.Count(value => value.OutputMemory is not null) <= 128,
                    "A NetAPI result lost its level-selected SDK array type or expansion limit.");
                foreach (var reference in returned.Where(value => value.Structure.Length > 0 &&
                    value.MemberOffset >= 0))
                {
                    var text = NetApiField(array, layout, reference.MemberOffset).Children.Single();
                    Require(text.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true,
                        "A NetAPI string lost its owning enumeration record and SDK field.");
                }
            }
            else if (family == "syncall")
            {
                var errors = row.Children.Single(value => value.Name == "Errors");
                var structure = ApiMetadata.Structure(row.SignatureType.Name)!;
                Require(errors.Children.Count == returned.Count(value => value.SyncPart == 2),
                    "Replication errors were combined or detached from their pointer-array indexes.");
                foreach (var descriptor in returned.Where(value => value.SyncPart == 2))
                {
                    var error = errors.Children.Single(value => value.Name == $"[{descriptor.ErrorIndex}]");
                    Require(error.OutputMemory?.Bytes.SequenceEqual(descriptor.Bytes) == true &&
                        structure.Fields!.All(field => error.Children.Any(value => value.Name == field.Name)),
                        "A replication error lost its descriptor or named SDK fields.");
                    foreach (var reference in returned.Where(value => value.SyncPart == 3 &&
                        value.ErrorIndex == descriptor.ErrorIndex))
                    {
                        var field = structure.Fields!.Single(value => value.Offset == reference.MemberOffset * 8);
                        var text = error.Children.Single(value => value.Name == field.Name).Children.Single();
                        Require(text.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true &&
                            (text.OutputText.StartsWith('"') || (reference.Flags & 2) != 0) && text.TypeName != "BSTR",
                            "A replication error string lost its server/source ownership or text type.");
                    }
                }
            }
            else if (family == "replica")
            {
                var capture = returned.Single(value => (value.Flags & 512) != 0 && value.MemberOffset < 0);
                var region = row.Children.Single(value => value.OutputMemory is { MemberOffset: < 0 } memory &&
                    memory.ReplicaType == capture.ReplicaType && (memory.Flags & 512) != 0);
                var structure = ApiMetadata.Structure(region.TypeName)!;
                var field = structure.Fields!.Single(value => ApiMetadata.Type(value.Type)?.Kind == "Array");
                var arrayLayout = ApiMetadata.Type(field.Type)!;
                var element = ApiMetadata.Type(arrayLayout.Element!)!;
                var array = region.Children.Single(value => value.Name == field.Name);
                var count = capture.OriginalBytes >= (ulong)(field.Offset / 8) ?
                    (capture.OriginalBytes - (uint)(field.Offset / 8)) / (uint)element.Size : 0;
                var expanded = array.Children.Where(value => value.OutputMemory is not null).ToArray();
                Require((ulong)expanded.Length <= count && expanded.Length <= 128 &&
                    expanded.All(value => value.OutputMemory!.Bytes.Length <= element.Size),
                    "A replication result expanded beyond the captured prefix or declared array count.");
                foreach (var reference in returned.Where(value => (value.Flags & 512) != 0 && value.MemberOffset >= 0))
                {
                    var relative = reference.MemberOffset - field.Offset / 8;
                    var owner = array.Children.Single(value => value.Name == $"[{relative / element.Size}]");
                    var member = element.Fields!.Single(value => value.Offset == relative % element.Size * 8);
                    var data = owner.Children.Single(value => value.Name == member.Name).Children.Single();
                    Require(data.OutputMemory?.Bytes.SequenceEqual(reference.Bytes) == true,
                        "A replication string or binary payload lost its owning array record and field.");
                    if (reference.Kind == 1)
                        Require(data.OutputText.StartsWith('"') && data.TypeName != "SID",
                            "A replication string was interpreted using another capture family's flags.");
                }
                if (count == 0) Require(array.Children.Count == 0,
                    "An empty replication result fabricated an array element.");
            }
            else if (family == "font-description")
            {
                var text = snapshots.Single(value => value.MemberOffset == 8);
                var field = nodes.Single(value => value.Name == "lpstrName");
                var child = field.Children.Single();
                Require(child.InputMemory?.Bytes.SequenceEqual(text.Bytes) == true &&
                    child.InputText.StartsWith("\"Segoe UI\"", StringComparison.Ordinal) &&
                    child.OutputMemory is null &&
                    child.InputText.Contains("truncated") == ((text.Flags & 1) != 0),
                    "A font name lost its owning field, quoted text or truncation state.");
            }
            else if (family == "marshal-array")
            {
                var output = item.GetProperty("output").GetBoolean();
                var captured = output ? returned : snapshots;
                var descriptor = captured.Single(value => value.Kind == 8);
                var data = captured.Single(value => value.Kind == 9);
                var array = row.Children.Single(value => value.TypeName == "SAFEARRAY");
                Require((output ? array.OutputMemory : array.InputMemory)?.Bytes
                    .SequenceEqual(descriptor.Bytes) == true,
                    "A marshalled array lost its recorded descriptor.");
                var dimensions = array.Children.Single(value => value.Name == "cDims");
                Require((output ? dimensions.Output : dimensions.Input) ==
                    MemorySnapshot.Scalar(descriptor.Bytes, 0, 2),
                    "A marshalled array lost its dimension count.");
                var elements = array.Children.Single(value => value.Name == "Elements");
                Require((output ? elements.OutputMemory : elements.InputMemory)?.Bytes
                    .SequenceEqual(data.Bytes) == true,
                    "A marshalled array lost its bounded elements.");
                var strings = captured.Where(value => value.Kind == 1 && (value.Flags & 32) != 0).ToArray();
                foreach (var text in strings)
                {
                    var element = elements.Children.Single(value => value.Name == $"[{text.ElementIndex}]");
                    var child = element.Children.Single(value => value.Name == "Text");
                    Require((output ? child.OutputMemory : child.InputMemory)?.Bytes
                        .SequenceEqual(text.Bytes) == true &&
                        (output ? child.OutputText : child.InputText).Contains(
                            text.Bytes.Length == 0 ? "\"\"" : "AB\\0CD"),
                        "A marshalled BSTR lost its element, embedded null or empty value.");
                }
            }
            else if (family == "certificate")
            {
                var output = parameter == 3;
                var captured = output ? returned : snapshots;
                if (captured.Length == 0)
                {
                    Require(nodes.All(value => value.InputMemory is null && value.OutputMemory is null),
                        "A failed certificate parse fabricated captured memory.");
                    continue;
                }
                var descriptor = captured.Single(value => value.Kind == 0 && value.MemberOffset < 0);
                var region = row.Children.Single(value => value.Children.Any(field => field.Name == "Version"));
                Require((output ? region.OutputMemory : region.InputMemory)?.Bytes
                    .SequenceEqual(descriptor.Bytes) == true && region.Children.Count == 8,
                    "A returned certificate lost its descriptor or SDK fields.");
                foreach (var (name, offset) in new[] { ("pszIssuer", 40), ("pszSubject", 48), ("pPublicKey", 56) })
                {
                    var field = region.Children.Single(value => value.Name == name);
                    if (descriptor.Bytes.Length < offset + 8)
                    {
                        Require((output ? field.Output : field.Input) is null && field.Children.Count == 0,
                            "A capped certificate descriptor fabricated a referenced field.");
                        continue;
                    }
                    var reference = captured.Single(value => value.MemberOffset == offset);
                    var child = field.Children.Single();
                    Require((output ? field.Output : field.Input) ==
                        MemorySnapshot.Scalar(descriptor.Bytes, offset, 8) &&
                        (output ? child.OutputMemory : child.InputMemory)?.Bytes
                            .SequenceEqual(reference.Bytes) == true,
                        "A certificate reference lost its owning field or recorded pointer.");
                    if (name != "pPublicKey")
                    {
                        Require((output ? child.OutputText : child.InputText)
                            .StartsWith("\"CN=Detourist Capture Test, O=Fixture\"", StringComparison.Ordinal),
                            "A certificate name lost its quoted ANSI text.");
                        continue;
                    }

                    // The key is one variable-length descriptor, with inline bytes after its count.
                    Require(child.TypeName == "PctPublicKey" && child.Children.Count == 3,
                        "A public key was expanded as an array of fixed-size descriptors.");
                    var count = child.Children.Single(value => value.Name == "cbKey");
                    var bytes = child.Children.Single(value => value.Name == "pKey");
                    Require((output ? count.Output : count.Input) == (ulong)(reference.Bytes.Length - 8) &&
                        (output ? bytes.OutputMemory : bytes.InputMemory)?.Bytes
                            .SequenceEqual(reference.Bytes[8..]) == true &&
                        bytes.Children.Count == reference.Bytes.Length - 8,
                        "A public key lost its declared count or inline key bytes.");
                    for (var index = 0; index < bytes.Children.Count; ++index)
                        Require((output ? bytes.Children[index].Output : bytes.Children[index].Input) ==
                            reference.Bytes[index + 8], "A public-key byte decoded incorrectly.");
                }
            }
            else if (family == "replication-schedule")
            {
                var capture = snapshots.Single(value => value.Kind == 0);
                var region = row.Children.Single(value => value.TypeName == "SCHEDULE");
                if (capture.Bytes.Length < 20)
                {
                    Require(region.Children.All(value => value.Name != "Schedule data [0]"),
                        "A partial replication schedule header fabricated offset-backed data.");
                    continue;
                }
                var data = region.Children.Single(value => value.Name == "Schedule data [0]");
                var offset = (int)MemorySnapshot.Scalar(capture.Bytes, 16, 4);
                Require((offset < capture.Bytes.Length ?
                    data.InputMemory?.Bytes.SequenceEqual(capture.Bytes[offset..]) == true &&
                        data.InputMemory.OriginalBytes == capture.OriginalBytes - (uint)offset :
                    data.InputMemory is null && data.InputText == "<not captured>") &&
                    data.TypeName == "byte[]" && region.Children.Any(value => value.Name == "Schedules"),
                    "A variable-size replication schedule lost its recorded offset-backed bytes or header.");
                if (data.InputMemory is { } payload && payload.OriginalBytes > (ulong)payload.Bytes.Length)
                    Require((payload.Flags & 1) != 0,
                        "A capped replication schedule payload lost its truncation state.");
            }
            else throw new InvalidOperationException("Unknown captured-buffer family.");
        }
        Console.WriteLine("Captured structured buffers and referenced array elements passed.");
    }

    private static void InspectPropertyVectors(JsonDocument details)
    {
        // Inspect real property vectors, including partial structures and unavailable element buffers.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var mode = item.GetProperty("mode").GetString();
            var limit = item.GetProperty("limit").GetInt32();
            var parameter = ParameterValues.Build(item.GetProperty("call")).Single(row => row.Parameter == 2);
            var vector = parameter.Children.Single(row => row.Name == "Vector");
            Require(parameter.Name == "[2] pv" && vector.OutputMemory is { Bytes.Length: 16 },
                "The property vector lost its named parameter or bounded descriptor.");
            var elements = vector.Children.Single(row => row.Name == "Elements");
            var visible = elements.Children.Where(row => !row.Name.Contains('…')).ToArray();
            var count = vector.Children.Single(row => row.Name == "cElems").Output;
            if (mode == "integer-vector")
            {
                Require(count == 6 && visible.Length == (limit == 16 ? 4 : 6) &&
                    visible[0].Output == unchecked((uint)-7) && visible[2].Output == 42 &&
                    visible[3].Output == 0x80000000 && visible[0].Type.Bits == 32,
                    "Integer vector values or capture bounds were decoded incorrectly.");
            }
            else if (mode == "float-vector")
                Require(count == 3 && BitConverter.UInt64BitsToDouble(visible[0].Output!.Value) == -3.25 &&
                    visible[0].Type.Kind == "Float64", "Floating property elements were not decoded.");
            else if (mode == "bool-vector")
                Require(count == 4 && visible.Length == 4 && visible[0].Output == 65535 &&
                    visible[1].Output == 0 && visible[0].Type.Kind == "Boolean",
                    "Boolean property elements were not decoded.");
            else if (mode == "guid-vector")
                Require(count == 2 && visible.Length == (limit == 16 ? 1 : 2) &&
                    visible[0].Children.Single(row => row.Name == "Data1").Output == 0x11223344 &&
                    visible[0].Children.Single(row => row.Name == "Data2").Output == 0x5566,
                    "GUID property elements did not expand their SDK fields.");
            else if (mode?.EndsWith("-string-vector", StringComparison.Ordinal) == true)
            {
                Require(count == 4 && visible.Length == Math.Min(4, (limit + 7) / 8),
                    "The string vector lost its bounded pointer elements.");
                var bstr = mode.StartsWith("bstr", StringComparison.Ordinal);
                var ansi = mode.StartsWith("ansi", StringComparison.Ordinal);
                var encoding = ansi ? System.Text.Encoding.Latin1 : System.Text.Encoding.Unicode;
                for (var index = 0; index < visible.Length; ++index)
                {
                    var element = visible[index];
                    if ((index + 1) * 8 > limit)
                    {
                        Require(element.Output is null && element.OutputMemory is
                            { Bytes.Length: 4, OriginalBytes: 8 } && element.Children.Count == 0,
                            "A partial pointer gained a string snapshot.");
                        continue;
                    }
                    var text = element.Children.Single(row => row.Name == "Text");
                    Require(text.OutputMemory is not null && text.TypeName ==
                        (bstr ? "BSTR" : ansi ? "LPSTR" : "LPWSTR"),
                        "A string lost its declared encoding or recorded data.");
                    if (index == 2)
                    {
                        Require(text.OutputText == "<unreadable>" &&
                            text.OutputMemory!.Bytes.Length == 0, "An invalid string gained readable text.");
                        continue;
                    }
                    var value = index == 1 ? "" : bstr ? "counted\0vector text" :
                        (index == 0 ? "vector property text" : "last vector text") + '\0';
                    var expected = encoding.GetBytes(value).Take(limit).ToArray();
                    var preview = encoding.GetString(expected);
                    if (!bstr) preview = preview.TrimEnd('\0');
                    Require(text.OutputMemory!.Bytes.SequenceEqual(expected) &&
                        text.OutputText.StartsWith('"' + preview.Replace("\0", "\\0") + '"',
                            StringComparison.Ordinal),
                        "String text, embedded NULs, or the null pointer were decoded incorrectly.");
                }
            }
            else if (mode is "vector" or "nested")
            {
                Require(count == 3 && visible.Length == (limit == 16 ? 1 : 3),
                    "Property variant expansion exceeded the captured element extent.");
                var fields = Flatten([visible[^1]]);
                Require(fields.Any(field => field.Name == "vt" && field.Output == 9),
                    "A captured property discriminator was lost.");
                var pointer = fields.Single(field => field.Name == "pdispVal");
                Require(limit != 56 ? pointer.Output is > 0 :
                    pointer.Output is null && pointer.OutputLabel == "<not captured>",
                    "A partial property element invented an uncaptured interface pointer.");
            }
            else if (mode == "empty-vector")
                Require(count == 0 && visible.Length == 0, "An empty property vector gained elements.");
            else if (mode == "invalid-vector")
                Require(count == 3 && visible.All(row => row.OutputMemory is null && row.Output is null),
                    "An unreadable property buffer gained captured values.");
        }
        Console.WriteLine("Property vector descriptors, typed elements and bounded structure expansion passed.");
    }

    private static void InspectPropertyStores(JsonDocument details)
    {
        // Real providers retain owned allocations as separate regions or per-element string children.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var written = call.Text("name") == "IPropertyStore::SetValue";
            var captured = call.Items(written ? "input" : "output")
                .Where(value => value.Number("parameter") == 2).Select(MemorySnapshot.FromJson).ToArray();
            var header = captured.Single(value => value.Kind == 0 && (value.Flags & 8) == 0);
            var tag = MemorySnapshot.Scalar(header.Bytes, 0, 2);
            var parameter = ParameterValues.Build(call).Single(row => row.Parameter == 2);
            MemorySnapshot? Snapshot(ParameterProperty value) =>
                written ? value.InputMemory : value.OutputMemory;
            var references = captured.Where(value => (value.Flags & 8) != 0).ToArray();
            if (tag is 0x1008 or 0x101F)
            {
                var elements = parameter.Children.Single(row => row.Name == "Vector")
                    .Children.Single(row => row.Name == "Elements");
                Require(elements.Children.SelectMany(row => row.Children).Count() == references.Length,
                    "Allocated property strings lost their element association.");
                foreach (var reference in references)
                {
                    var text = elements.Children.Single(row => row.Name == $"[{reference.ElementIndex}]")
                        .Children.Single(row => row.Name == "Text");
                    Require(Snapshot(text)?.Bytes.SequenceEqual(reference.Bytes) == true &&
                        (written ? text.InputText : text.OutputText).StartsWith('"'),
                        "An allocated string lost its captured bytes or text preview.");
                }
            }
            else
            {
                var regions = parameter.Children.Where(row => Snapshot(row) is { Flags: var flags } &&
                    (flags & 8) != 0).ToArray();
                Require(regions.Length == references.Length, "An owned property allocation was omitted.");
                for (var index = 0; index < regions.Length; ++index)
                    Require(Snapshot(regions[index])!.Bytes.SequenceEqual(references[index].Bytes) &&
                        regions[index].Children.Count == 0 && regions[index].TypeName.StartsWith("byte[",
                            StringComparison.Ordinal), "Binary property data gained invented variant fields.");
            }
        }
        Console.WriteLine("Property store allocations, string previews and bounded binary regions passed.");
    }

    private static void InspectPropertyGraphs(JsonDocument details)
    {

        // Live captures must preserve mixed container relationships and the type of each scalar allocation.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var mode = item.Text("mode");
            var limit = item.Number("limit");
            var parameter = ParameterValues.Build(call).Single(row => row.Parameter == 2);
            var rows = new List<ParameterProperty> { parameter };
            for (var index = 0; index < rows.Count; ++index)
            {
                Require(rows[index].Children.All(child => child.Level == rows[index].Level + 1),
                    "A nested value retained indentation from a different parent.");
                rows.AddRange(rows[index].Children);
            }
            var arrays = rows.Where(row => row.OutputMemory?.Kind is 8 or 10)
                .ToDictionary(row => row.OutputMemory!.ArrayIndex);
            if (mode == "graph")
            {
                Require(arrays.Count == (limit < 40 ? 1 : limit < 96 ? 3 : 5) &&
                    parameter.Children.Count(row => row.OutputMemory?.Kind is 8 or 10) == 1,
                    "Nested arrays remained unrelated parameter regions or lost an identity.");
                ParameterProperty Element(int array, int index) => arrays[array].Children
                    .Single(row => row.Name == "Elements").Children.Single(row => row.Name == $"[{index}]");
                foreach (var array in arrays.Values.Where(row => row.OutputMemory!.ParentArrayIndex >= 0))
                {
                    var descriptor = array.OutputMemory!;
                    Require(Element(descriptor.ParentArrayIndex, descriptor.ParentElementIndex)
                        .Children.Contains(array), "An array was attached to the wrong element.");
                }
                foreach (var captured in call.Items("output").Select(MemorySnapshot.FromJson)
                    .Where(value => (value.Flags & 32) != 0))
                {
                    var element = Element(captured.ArrayIndex, captured.ElementIndex);
                    var reference = element.Children.Single(row => row.OutputMemory?.Kind == captured.Kind &&
                        row.OutputMemory?.Flags == captured.Flags &&
                        row.OutputMemory?.Bytes.SequenceEqual(captured.Bytes) == true);
                    var tag = captured.VariantType & 0xFFF;
                    Require(reference.Name == (tag is 8 or 30 or 31 ? "Text" :
                        captured.Kind == 14 ? "Clipboard" : "Data"),
                        "An allocation was displayed with the wrong meaning.");
                    if ((captured.Flags & 2) != 0)
                        Require(reference.OutputText == "<unreadable>", "Unreadable text became a value.");
                    else if (tag is 8 or 30 or 31)
                    {
                        var encoding = tag == 30 ? System.Text.Encoding.Latin1 : System.Text.Encoding.Unicode;
                        var text = encoding.GetString(captured.Bytes);
                        if (tag != 8) text = text.TrimEnd('\0');
                        Require(reference.OutputText.StartsWith('"' + text.Replace("\0", "\\0") + '"'),
                            "A nested string lost its encoding, terminator handling or embedded NUL.");
                    }
                    else if (tag == 72)
                        Require(reference.Children.Single(row => row.Name == "Data1").Output == 0x9DC27815,
                            "An allocated GUID lost its SDK fields.");
                    else if (captured.Kind == 14)
                        Require(reference.Children.Single(row => row.Name == "cbSize").Output == 100,
                            "A clipboard allocation lost its header.");
                    else Require(reference.Children.Count == 0, "Binary payload acquired invented fields.");
                }
                if (limit == 256)
                {
                    var grid = new ParameterGrid();
                    grid.ShowCall(call);
                    Elements(grid).OfType<Button>().Single(button =>
                        button.ToolTip as string == "Expand all properties")
                        .RaiseEvent(new RoutedEventArgs(
                            System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
                    var properties = (DataGrid)grid.FindName("PropertiesGrid");
                    foreach (var row in properties.Items.Cast<ParameterProperty>())
                        row.Expanded = row.Parameter == 2 || row.Level > 0 &&
                            (row.Name is "Elements" or "Text" || row.OutputMemory?.Kind is 8 or 10 ||
                            row.Name.StartsWith('['));
                    typeof(ParameterGrid).GetMethod("Rebuild", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .Invoke(grid, null);
                    var depth = properties.Items.Cast<ParameterProperty>().Max(row => row.Level);
                    Require(depth >= 8 && properties.Columns[0].MinWidth > depth * 13 + 35,
                        "Deep indentation consumed the property column.");
                    foreach (var (width, scale) in new[] { (1000, 1.0), (600, 1.0), (1000, 1.5) })
                    {
                        grid.LayoutTransform = new ScaleTransform(scale, scale);
                        var host = new Border { Child = grid,
                            Background = (Brush)Application.Current.FindResource("CanvasBrush") };
                        host.Measure(new Size(width, 760));
                        host.Arrange(new Rect(0, 0, width, 760));
                        host.UpdateLayout();
                        for (var pass = 0; pass < 2; ++pass)
                        {
                            var frame = new DispatcherFrame();
                            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,
                                new Action(() => frame.Continue = false));
                            Dispatcher.PushFrame(frame);
                            host.UpdateLayout();
                        }
                        Require(properties.Columns[0].ActualWidth >= properties.Columns[0].MinWidth,
                            "The nested property column did not apply its minimum width.");
                        var names = Elements(properties).OfType<DockPanel>()
                            .Where(panel => panel.DataContext is ParameterProperty);
                        Require(names.All(panel => panel.ActualWidth >= 20),
                            "A captured property lost its expansion control at an alternate width or scale.");
                        var directory = Environment.GetEnvironmentVariable("DETOURIST_TEST_ARTIFACTS");
                        if (!string.IsNullOrEmpty(directory))
                        {
                            Directory.CreateDirectory(directory);
                            var bitmap = new RenderTargetBitmap(width, 760, 96, 96, PixelFormats.Pbgra32);
                            bitmap.Render(host);
                            SavePng(bitmap, Path.Combine(directory, $"property-graph-{width}-{scale}.png"));
                        }
                        host.Child = null;
                    }
                }
            }
            else if (mode is "referenced-scalars" or "clipboard-vector" or "property-helpers")
            {
                Require(arrays.Count == 1, "A scalar vector lost its container.");
                var elements = arrays[0].Children.Single(row => row.Name == "Elements");
                foreach (var captured in call.Items("output").Select(MemorySnapshot.FromJson)
                    .Where(value => (value.Flags & 32) != 0 && value.Kind != 14))
                {
                    var element = elements.Children.Single(row => row.Name == $"[{captured.ElementIndex}]");
                    var data = element.Children.Single(row => row.Name == "Data");
                    Require(data.OutputMemory!.Bytes.SequenceEqual(captured.Bytes),
                        "A referenced scalar lost its bytes or parent element.");
                    if ((captured.Flags & 2) != 0)
                        Require(data.OutputText == "<unreadable>", "An invalid scalar became a value.");
                    else if (mode == "referenced-scalars")
                    {
                        data.Hex = false;
                        var expected = captured.ElementIndex switch { 0 or 6 => "-78921", 1 => "-2.5",
                            2 => "True (65535)", _ => null };
                        if (expected is not null)
                            Require(data.OutputText == expected, "A scalar lost its signed or floating type.");
                        else Require(data.TypeName == "DECIMAL" && data.Children.Count > 0,
                            "A decimal reference lost its SDK fields.");
                    }
                }
            }
            else
            {
                Require(arrays.Count == 0, "A cycle or clipboard payload acquired an invented array.");
                if (mode.StartsWith("clipboard", StringComparison.Ordinal) && mode != "clipboard-null")
                {
                    var header = parameter.Children.Single(row => row.OutputMemory?.Kind == 14);
                    Require(header.TypeName == "CLIPDATA" &&
                        header.Children.Select(row => row.Name)
                            .SequenceEqual(["cbSize", "ulClipFmt", "pClipData"]),
                        "A clipboard descriptor lost its expandable SDK layout.");
                    Require(parameter.Children.Where(row => row.OutputMemory is { Kind: 0, Flags: var flags } &&
                        (flags & 8) != 0).All(row => row.Children.Count == 0),
                        "A clipboard payload was expanded as property variants.");
                }
            }
        }
        Console.WriteLine("Nested arrays, typed allocations, clipboard layouts " +
            "and inspector hierarchy passed.");
    }

    private static void InspectPropertyVariants(JsonDocument details)
    {
        // Property snapshots expose their SDK discriminator and interface-pointer union fields.
        var call = details.RootElement.EnumerateArray().Single();
        var value = ParameterValues.Build(call).Single(row => row.Parameter == 2);
        var memory = value.Children.Single();
        Require(value.Name == "[2] pv" && memory.OutputMemory is { Bytes.Length: 24, OriginalBytes: 24 },
            "The property value did not retain its named, bounded SDK snapshot.");
        var fields = Flatten([memory]);
        Require(fields.Any(field => field.Name == "vt" && field.Output == 9) &&
            fields.Any(field => field.Name == "pdispVal" && field.Output is > 0),
            "The property variant did not expand its discriminator and returned interface pointer.");
        Console.WriteLine("Property variant parameter names, bounded snapshots and SDK union fields passed.");
    }
}
