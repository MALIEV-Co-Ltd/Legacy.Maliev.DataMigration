namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapRehearsalAcceptanceTests
{
    [Fact]
    public async Task Caller_cannot_construct_a_reviewed_invocation_or_supply_fake_completion_to_the_console_factory()
    {
        var completion = new CounterfeitCompletion();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => Console.ConsumerColumnBootstrapReviewedInvocation.CreateAsync(
            "not-a-path", completion, default));
        Assert.Equal(0, completion.Invocations);
    }

    [Fact]
    public void Caller_implemented_completion_is_rejected_before_it_can_supply_evidence()
    {
        var completion = new CounterfeitCompletion();
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapRehearsalAcceptance.Read(completion));
        Assert.Equal(0, completion.Invocations);
    }

    // A test double can exercise refusal; it cannot mint the private accepted token.
    private sealed class CounterfeitCompletion : IConsumerColumnBootstrapRehearsalCompletion
    {
        internal int Invocations { get; private set; }
        public ConsumerColumnBootstrapRehearsalEvidence ReadEvidence()
        {
            Invocations++;
            throw new InvalidOperationException("Untrusted evidence callback must not be invoked.");
        }
    }
}
