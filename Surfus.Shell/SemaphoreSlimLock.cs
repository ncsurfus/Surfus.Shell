using System;
using System.Threading;
using System.Threading.Tasks;

namespace Surfus.Shell
{
    /// <summary>
    /// Represents a use of the SemaphoreSlimSingle.
    /// </summary>
    internal class SemaphoreSlimLock : IDisposable
    {
        /// <summary>
        /// The underlying _semaphoreSlim.
        /// </summary>
        internal SemaphoreSlim _semaphoreSlim;

        /// <summary>
        /// Tracks if this object has been disposed of.
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="semaphoreSlim"></param>
        internal SemaphoreSlimLock(SemaphoreSlim semaphoreSlim)
        {
            _semaphoreSlim = semaphoreSlim;
        }

        /// <summary>
        /// Releases the SemaphoreSlim connection count.
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
}
