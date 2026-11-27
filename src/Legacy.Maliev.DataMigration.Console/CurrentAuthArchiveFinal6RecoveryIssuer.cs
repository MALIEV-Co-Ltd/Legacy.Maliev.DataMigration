using System.Reflection;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveRecoveryV2Issuer
{
    internal static async Task<CurrentAuthArchiveRecoveryV2Issuer> CreateFinal6RecoveryAsync(CurrentAuthArchiveFinal6CaseContext context,
        CurrentAuthArchiveRecoveryV2Case expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (CurrentAuthArchiveGeneratedCasesV2.Recovery(context.Case) != expected) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        await context.RequireFactoryAsync(ct);
        var request = context.Request;
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path)!, ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null;
        ICurrentAuthArchiveRecoveryV2Lease? lease = null;
        try
        {
            bundle.Require();
            Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies().Where(assembly => assembly.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
            if (loaded.Length > 1) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            Assembly tests;
            if (loaded.Length == 0)
            { loader = new(request.Inputs.TestImage.Path); tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path); }
            else
            {
                tests = loaded[0];
                if (!StringComparer.OrdinalIgnoreCase.Equals(tests.Location, request.Inputs.TestImage.Path)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
                using var image = SecureLocalFile.OpenReadShared(tests.Location);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(image, request.Inputs.TestImage.Path) ||
                    Convert.ToHexStringLower(SHA256.HashData(image)) != request.Inputs.TestImage.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            }
            Type exact = tests.GetType(LeaseType, throwOnError: true)!;
            if (!exact.IsSealed || exact.Assembly != tests || exact.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length != 0)
            { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            MethodInfo factory = exact.GetMethod("OpenFinal6RecoveryLeaseAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                binder: null, types: [typeof(CurrentAuthArchiveFinal6CaseContext), typeof(CurrentAuthArchiveRecoveryV2Case), typeof(CancellationToken)], modifiers: null)
                ?? throw CurrentAuthArchiveFinal6Source.Invalid();
            if (factory.ReturnType != typeof(Task<ICurrentAuthArchiveRecoveryV2Lease>)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            await context.RequireFactoryAsync(ct); bundle.Require();
            lease = await ((Task<ICurrentAuthArchiveRecoveryV2Lease>?)factory.Invoke(null, [context, expected, ct]) ?? throw CurrentAuthArchiveFinal6Source.Invalid());
            if (lease.GetType() != exact) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            var issuer = new CurrentAuthArchiveRecoveryV2Issuer(bundle, loader, lease);
            _ = await issuer.ObserveAsync(baseline: true, ct);
            bundle.Require(); return issuer;
        }
        catch (Exception primary)
        {
            try { if (lease is not null) { await lease.DisposeAsync(); } } catch (Exception failure) { primary.Data["final6_helper_pair_cleanup"] = failure.GetType().Name; }
            try { loader?.Unload(); } catch (Exception failure) { primary.Data["final6_helper_unload"] = failure.GetType().Name; }
            try { loader?.Dispose(); } catch (Exception failure) { primary.Data["final6_helper_loader_cleanup"] = failure.GetType().Name; }
            try { bundle.Dispose(); } catch (Exception failure) { primary.Data["final6_helper_bundle_cleanup"] = failure.GetType().Name; }
            throw;
        }
    }
}
