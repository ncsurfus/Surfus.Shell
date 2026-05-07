namespace Surfus.Shell.Tests;

/// <summary>
/// Integration tests that start a Go SSH server share this collection
/// to avoid resource contention from parallel process spawning.
/// </summary>
[CollectionDefinition("Integration")]
public class IntegrationTestCollection;
