# syntax=docker/dockerfile:1.7

# Both build arguments must be complete registry references pinned by sha256.
# scripts/build-exact24-shadow-runner.ps1 validates that contract before Docker runs.
ARG DOTNET_SDK_IMAGE
ARG DOTNET_RUNTIME_IMAGE
FROM ${DOTNET_SDK_IMAGE} AS build

WORKDIR /source
COPY src/Legacy.Maliev.DataMigration/Legacy.Maliev.DataMigration.csproj src/Legacy.Maliev.DataMigration/
COPY src/Legacy.Maliev.DataMigration.Console/Legacy.Maliev.DataMigration.Console.csproj src/Legacy.Maliev.DataMigration.Console/
RUN dotnet restore src/Legacy.Maliev.DataMigration.Console/Legacy.Maliev.DataMigration.Console.csproj

COPY src/ src/
RUN dotnet publish src/Legacy.Maliev.DataMigration.Console/Legacy.Maliev.DataMigration.Console.csproj \
    --configuration Release --no-restore --output /runner \
    -p:UseAppHost=false -p:ContinuousIntegrationBuild=true

FROM ${DOTNET_RUNTIME_IMAGE} AS runtime

WORKDIR /runner
COPY --from=build /runner/ ./

USER 65532:65532

ENTRYPOINT ["dotnet", "Legacy.Maliev.DataMigration.Console.dll"]
