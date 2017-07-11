using Surfus.Shell;
using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Represents a SemaphoreSlim with a single concurrent request.
/// </summary>
internal class SemaphoreSlimSingle : IDisposable
{
    /// <summary>
    /// The internal Semaphore.
    /// </summary>
    private SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

    /// <summary>
    /// Tracks if this object has been disposed of.
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Constructor.
    /// </summary>
    internal SemaphoreSlimSingle()
    {
    }

    /// <summary>
    /// Awaits to enter the Semaphore.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    internal async Task<SemaphoreSlimLock> WaitAsync(CancellationToken cancellationToken)
    {
        await _semaphoreSlim.WaitAsync(cancellationToken);
        return new SemaphoreSlimLock(_semaphoreSlim);
    }

    /// <summary>
    /// Disposes the SemaphoreSlimSingle.
    /// </summary>
    public void Dispose()
    {
        if(!_disposed)
        {
            _disposed = true;
            _semaphoreSlim.Release();
        }
    }
}