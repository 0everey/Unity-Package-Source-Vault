// Offline metadata reader. Target bytes are only passed to PEReader in memory.
// Do not add Assembly.Load, dependency resolution, reflection invocation or execution.
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed record InputItem(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("base64")] string Base64);

internal static class Program
{
    private const int MaxBinaryBytes = 32 * 1024 * 1024;
    private const int MaxJsonCharacters = 48 * 1024 * 1024;
    private const int MaxTypeRows = 50000;
    private const int MaxMethodRows = 250000;

    private static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static bool SafePath(string? path) => !string.IsNullOrEmpty(path)
        && !path.StartsWith('/') && !path.Contains('\\') && !path.Contains(':') && !path.Contains('\0')
        && !path.Split('/').Any(part => part is "" or "." or "..");

    private static string? Token(byte[] value, bool wholeKey)
    {
        if (value.Length == 0) return null;
        if (wholeKey)
        {
            byte[] digest = SHA1.HashData(value);
            return Convert.ToHexString(digest[^8..].Reverse().ToArray()).ToLowerInvariant();
        }
        if (value.Length != 8) throw new BadImageFormatException();
        return Convert.ToHexString(value).ToLowerInvariant();
    }

    private static Dictionary<string, object?> Identity(MetadataReader reader, AssemblyDefinition value) => new()
    {
        ["name"] = reader.GetString(value.Name), ["version"] = value.Version.ToString(),
        ["culture"] = value.Culture.IsNil ? "neutral" : EmptyCulture(reader.GetString(value.Culture)),
        ["publicKeyToken"] = Token(reader.GetBlobBytes(value.PublicKey), wholeKey: true)
    };

    private static Dictionary<string, object?> Identity(MetadataReader reader, AssemblyReference value) => new()
    {
        ["name"] = reader.GetString(value.Name), ["version"] = value.Version.ToString(),
        ["culture"] = value.Culture.IsNil ? "neutral" : EmptyCulture(reader.GetString(value.Culture)),
        ["publicKeyToken"] = Token(reader.GetBlobBytes(value.PublicKeyOrToken), (value.Flags & AssemblyFlags.PublicKey) != 0)
    };

    private static string EmptyCulture(string culture) => culture.Length == 0 ? "neutral" : culture;

    private static (string FullName, string Namespace) TypeName(MetadataReader reader, TypeDefinitionHandle handle, int depth = 0)
    {
        if (depth > 128) throw new BadImageFormatException();
        TypeDefinition definition = reader.GetTypeDefinition(handle);
        string name = reader.GetString(definition.Name);
        TypeDefinitionHandle parent = definition.GetDeclaringType();
        if (!parent.IsNil)
        {
            var outer = TypeName(reader, parent, depth + 1);
            return (outer.FullName + "+" + name, outer.Namespace);
        }
        string ns = reader.GetString(definition.Namespace);
        return (ns.Length == 0 ? name : ns + "." + name, ns);
    }

    private static string BaseTypeName(MetadataReader reader, EntityHandle handle)
    {
        if (handle.Kind == HandleKind.TypeReference)
        {
            TypeReference reference = reader.GetTypeReference((TypeReferenceHandle)handle);
            return reader.GetString(reference.Namespace) + "." + reader.GetString(reference.Name);
        }
        if (handle.Kind == HandleKind.TypeDefinition)
            return TypeName(reader, (TypeDefinitionHandle)handle).FullName;
        return "";
    }

    private static string TypeKind(MetadataReader reader, TypeDefinition definition)
    {
        if ((definition.Attributes & TypeAttributes.Interface) != 0) return "interface";
        return BaseTypeName(reader, definition.BaseType) switch
        {
            "System.Enum" => "enum", "System.ValueType" => "struct",
            "System.Delegate" or "System.MulticastDelegate" => "delegate", _ => "class"
        };
    }

    private static Dictionary<string, object?> Inspect(InputItem item)
    {
        if (!SafePath(item.Path)) throw new ArgumentException("Input paths must be relative POSIX paths");
        byte[] data;
        try { data = Convert.FromBase64String(item.Base64); }
        catch (FormatException)
        {
            return new() { ["path"] = item.Path, ["metadataStatus"] = "invalid-input", ["metadataError"] = "invalid-base64" };
        }
        Dictionary<string, object?> result = new()
        {
            ["path"] = item.Path, ["sha256"] = Sha(data), ["size"] = data.Length,
            ["metadataProducer"] = new { name = "uvault.managed-index", version = "1", reader = "System.Reflection.Metadata/PEReader" },
            ["assemblyIdentity"] = null, ["references"] = Array.Empty<object>(), ["types"] = Array.Empty<object>(),
            ["dummyDll"] = false, ["profileVerified"] = false
        };
        if (data.Length > MaxBinaryBytes)
        {
            result["metadataStatus"] = "unavailable";
            result["metadataError"] = "binary-exceeds-metadata-input-limit";
            return result;
        }
        try
        {
            using MemoryStream stream = new(data, writable: false);
            using PEReader pe = new(stream, PEStreamOptions.LeaveOpen);
            if (!pe.HasMetadata)
            {
                result["metadataStatus"] = "native-binary";
                return result;
            }
            MetadataReader reader = pe.GetMetadataReader();
            if (reader.AssemblyReferences.Count > 10000 || reader.TypeDefinitions.Count > MaxTypeRows || reader.MethodDefinitions.Count > MaxMethodRows)
            {
                result["metadataStatus"] = "unavailable";
                result["metadataError"] = "metadata-table-exceeds-resource-limit";
                return result;
            }
            List<Dictionary<string, object?>> references = reader.AssemblyReferences.Select(handle => Identity(reader, reader.GetAssemblyReference(handle)))
                .OrderBy(value => value["name"]?.ToString(), StringComparer.Ordinal)
                .ThenBy(value => value["version"]?.ToString(), StringComparer.Ordinal).ToList();
            result["references"] = references;
            if (reader.IsAssembly) result["assemblyIdentity"] = Identity(reader, reader.GetAssemblyDefinition());
            result["dummyDll"] = references.Any(value => string.Equals(value["name"]?.ToString(), "Il2CppDummyDll", StringComparison.Ordinal))
                || (reader.IsAssembly && reader.GetString(reader.GetAssemblyDefinition().Name) == "Il2CppDummyDll");
            List<Dictionary<string, object?>> types = new();
            foreach (TypeDefinitionHandle handle in reader.TypeDefinitions)
            {
                TypeDefinition definition = reader.GetTypeDefinition(handle);
                if (reader.GetString(definition.Name) == "<Module>") continue;
                var name = TypeName(reader, handle);
                List<Dictionary<string, object?>> methods = new();
                foreach (MethodDefinitionHandle methodHandle in definition.GetMethods())
                {
                    MethodDefinition method = reader.GetMethodDefinition(methodHandle);
                    BlobReader signature = reader.GetBlobReader(method.Signature);
                    SignatureHeader header = signature.ReadSignatureHeader();
                    if (header.IsGeneric) signature.ReadCompressedInteger();
                    int parameterCount = signature.ReadCompressedInteger();
                    methods.Add(new()
                    {
                        ["name"] = reader.GetString(method.Name), ["arity"] = method.GetGenericParameters().Count,
                        ["parameterCount"] = parameterCount, ["signatureBlobSha256"] = Sha(reader.GetBlobBytes(method.Signature))
                    });
                }
                methods = methods.OrderBy(value => value["name"]?.ToString(), StringComparer.Ordinal)
                    .ThenBy(value => (int)value["arity"]!).ThenBy(value => (int)value["parameterCount"]!)
                    .ThenBy(value => value["signatureBlobSha256"]?.ToString(), StringComparer.Ordinal).ToList();
                types.Add(new() { ["fullName"] = name.FullName, ["namespace"] = name.Namespace,
                    ["kind"] = TypeKind(reader, definition), ["methods"] = methods });
            }
            result["types"] = types.OrderBy(value => value["fullName"]?.ToString(), StringComparer.Ordinal).ToList();
            result["metadataStatus"] = reader.IsAssembly ? "managed" : "managed-module";
            result["methodSignatureBasis"] = "metadata-blob-hash-is-weak-token-local-evidence-not-cross-assembly-signature-equivalence";
        }
        catch (Exception error) when (error is BadImageFormatException or InvalidOperationException or ArgumentOutOfRangeException or IOException)
        {
            result["metadataStatus"] = "invalid-binary";
            result["metadataError"] = "invalid-or-unsupported-PE-metadata";
            result["assemblyIdentity"] = null;
            result["references"] = Array.Empty<object>();
            result["types"] = Array.Empty<object>();
            result["dummyDll"] = false;
        }
        return result;
    }

    private static int Main()
    {
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = new UTF8Encoding(false);
        try
        {
            StringBuilder input = new();
            char[] buffer = new char[64 * 1024];
            int read;
            while ((read = Console.In.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (input.Length + read > MaxJsonCharacters) throw new ArgumentException("Input batch exceeds metadata limit");
                input.Append(buffer, 0, read);
            }
            List<InputItem> items = JsonSerializer.Deserialize<List<InputItem>>(input.ToString())
                ?? throw new ArgumentException("Input must be a JSON list");
            if (items.Count > 128 || items.Any(item => item is null || !SafePath(item.Path))) throw new ArgumentException("Invalid input batch");
            Console.WriteLine(JsonSerializer.Serialize(items.Select(Inspect).ToList()));
            return 0;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or OutOfMemoryException)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { error = "invalid-metadata-input", kind = error.GetType().Name }));
            return 2;
        }
    }
}
