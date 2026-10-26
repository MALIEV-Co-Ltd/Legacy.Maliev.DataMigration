using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoIndexVectorTests
{
    [Theory]
    [InlineData("[1978]")]
    [InlineData("[\"1978\"]")]
    [InlineData("\"1978\"")]
    public void Actual_numeric_or_OID_string_array_and_exact_text_are_bound(string json)
    { Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(Row(json), "vector", [1978])); }

    [Fact]
    public void Actual_primary_vectors_bind_exact_ordinal_oid_collation_and_options()
    {
        var row = JsonNode.Parse("{\"indkey\":[4],\"indclass\":[\"1978\"],\"indcollation\":[\"0\"],\"indoption\":[0]}")!.AsObject();
        Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indkey", [4]));
        Assert.False(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indkey", [1]));
        Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indclass", [1978]));
        Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indcollation", [0]));
        Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indoption", [0]));
        Assert.False(CurrentOwnerIsoNativePreservation.VectorEquals(row, "indclass", [1981]));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[1978,1978]")]
    [InlineData("[1979]")]
    [InlineData("[-1978]")]
    [InlineData("[true]")]
    [InlineData("[null]")]
    [InlineData("[[1978]]")]
    [InlineData(/*lang=json,strict*/ "[{\"oid\":1978}]")]
    [InlineData("[1978.0]")]
    [InlineData("[1.978e3]")]
    [InlineData("[\"01978\"]")]
    [InlineData("[\"+1978\"]")]
    [InlineData("[\" 1978\"]")]
    [InlineData("[\"4294967296\"]")]
    [InlineData("1978")]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("\"1978 \"")]
    public void Malformed_or_extra_or_noncanonical_or_wrong_operands_are_rejected(string json)
    { Assert.False(CurrentOwnerIsoNativePreservation.VectorEquals(Row(json), "vector", [1978])); }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("[\"1\",\"2\"]")]
    [InlineData("\"1 2\"")]
    public void Two_element_vectors_keep_length_and_order(string json)
    {
        Assert.True(CurrentOwnerIsoNativePreservation.VectorEquals(Row(json), "vector", [1, 2]));
        Assert.False(CurrentOwnerIsoNativePreservation.VectorEquals(Row(json), "vector", [2, 1]));
        Assert.False(CurrentOwnerIsoNativePreservation.VectorEquals(Row(json), "vector", [1]));
    }

    private static JsonObject Row(string json)
    {
        return new() { ["vector"] = JsonNode.Parse(json) };
    }
}
