using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Simple in-memory public key store for caching keys that have been used to verify tokens.
    /// Includes a callback property for retrieving more keys.
    /// </summary>
    public class PublicKeyCache : IDisposable
    {
        #region Private Fields

        /// <summary>
        /// Trusted public keys, by KID.
        /// </summary>
        private IDictionary<string, SecurityKey> _trustedkeysbykid;

        private object _lock;
        private bool disposedValue;

        #endregion


        #region Public Properties

        /// <summary>
        /// Callback signature for a key retrieval method.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public delegate (int res, SecurityKey data) dKeyRetrieval(string kid);

        /// <summary>
        /// Set a callback to this property, that the key cache will use to 
        /// </summary>
        public dKeyRetrieval? KeyRetrievalCallback { get; set; }

        #endregion


        #region ctor / dtor

        /// <summary>
        /// Public constructor
        /// </summary>
        public PublicKeyCache()
        {
            _lock = new object();
            _trustedkeysbykid = new Dictionary<string, SecurityKey>(StringComparer.Ordinal);
            KeyRetrievalCallback = null;
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~PublicKeyCache()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        /// Public Dispose method
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Private dispose call, doing the work.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // Clear any callbacks...
                this.KeyRetrievalCallback = null;

                // Clear the keyring...
                this._trustedkeysbykid.Clear();
                this._trustedkeysbykid = null;


                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        #endregion


        #region Public Methods

        /// <summary>
        /// Accessor to insert a key into the cache.
        /// Usually used for testing.
        /// Will return errors if the kid exists, is blank, or key is null.
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public int AddKey(string kid, SecurityKey data)
        {
            if (disposedValue)
                return -2;

            try
            {
                if(string.IsNullOrWhiteSpace(kid))
                    return -1;
                if(data == null)
                    return -1;

                lock( _lock)
                {
                    if (this._trustedkeysbykid.ContainsKey(kid))
                        return -1;

                    this._trustedkeysbykid.Add(kid, data);
                    return 1;
                }
            }
            catch(Exception e)
            {
                return -2;
            }
        }

        /// <summary>
        /// Public method to get a key by its kid.
        /// This method will check the local key list.
        /// If not found, it will use the callback, if set, to pull down the key, store it, and return it.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public (int res, SecurityKey? data) GetKey(string kid)
        {
            if (disposedValue)
                return (-2, null);

            try
            {
                if(string.IsNullOrWhiteSpace(kid))
                    return (-1, null);

                // Do a get outside the lock for speed...
                if (this._trustedkeysbykid.TryGetValue(kid, out var val))
                    return (1, val);
                // If here, the kid wasn't found.

                // Enter the lock...
                lock( _lock)
                {
                    // Inside the sync lock...

                    // Do a get inside the lock, to be sure...
                    if (this._trustedkeysbykid.TryGetValue(kid, out val))
                        return (1, val);
                    // Key isn't here.


                    // See if we were given a callback to use, for pulling down new keys...
                    if(this.KeyRetrievalCallback == null)
                    {
                        // No callback to use.
                        return (-1, null);
                    }
                    // Have a callback to try.

                    // We will attempt to pull it down, and cache it...
                    // Wrap in a catch, to swallow exceptions if the delegate throws.
                    try
                    {
                        var rescall = this.KeyRetrievalCallback(kid);
                        if(rescall.res != 1 || rescall.data == null)
                        {
                            // Callback failed to get key.
                            // Regard it as failure.
                            return (-1, null);
                        }
                        // If here, the callback gave us a key.

                        // Add it to local store...
                        this._trustedkeysbykid.Add(kid, rescall.data);

                        // And, return it to the caller...
                        return (1, rescall.data);
                    }
                    catch(Exception e)
                    {
                        // Callback threw.
                        // Regard it as failure.
                        return (-1, null);
                    }
                }
            }
            catch(Exception e)
            {
                return (-2, null);
            }
        }

        /// <summary>
        /// Use this to remove a key by its kid.
        /// </summary>
        /// <param name="kid"></param>
        public void DeleteKey(string kid)
        {
            if (disposedValue)
                return;

            try
            {
                lock( _lock)
                {
                    this._trustedkeysbykid.Remove(kid);
                }
            }
            catch(Exception e)
            {
                return;
            }
        }

        #endregion
    }
}
