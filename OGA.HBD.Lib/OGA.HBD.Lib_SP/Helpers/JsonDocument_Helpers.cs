using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace OGA.HBD.Helpers
{
    /// <summary>
    /// Contains some consolidated methods for accessing properties of JsonDocuments and JsonObjects.
    /// </summary>
    static public class JsonDocument_Helpers
    {
        static public bool TryGetObject(JsonElement root, string propname, out JsonElement obj)
        {
            if (root.TryGetProperty(propname, out var el) && el.ValueKind == JsonValueKind.Object)
            {
                obj = el;
                return true;
            }

            obj = default;
            return false;
        }

        static public bool TryGetString(JsonElement element, string propname, out string val)
        {
            val = null;
            try
            {
                if(string.IsNullOrWhiteSpace(propname))
                    return false;

                // Get the property element...
                if(!element.TryGetProperty(propname, out var valEL))
                    return false;

                // Verify its type...
                if(valEL.ValueKind != JsonValueKind.String)
                    return false;

                var tmp = valEL.GetString();
                if(string.IsNullOrEmpty(tmp))
                    return false;

                val = tmp;
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }

        static public bool TryGetLong(JsonElement element, string propname, out long val)
        {
            val = 0;
            try
            {
                if(string.IsNullOrWhiteSpace(propname))
                    return false;

                // Get the property element...
                if(!element.TryGetProperty(propname, out var valEL))
                    return false;

                // Verify its type...
                if(valEL.ValueKind != JsonValueKind.Number)
                    return false;

                val = valEL.GetInt64();
                //if(tmp == null)
                //    return false;

                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }

        static public bool TryGetInt32(JsonElement element, string propname, out int val)
        {
            val = 0;
            try
            {
                if(string.IsNullOrWhiteSpace(propname))
                    return false;

                // Get the property element...
                if(!element.TryGetProperty(propname, out var valEL))
                    return false;

                // Verify its type...
                if(valEL.ValueKind != JsonValueKind.Number)
                    return false;

                var tmp = valEL.GetInt32();
                //if(tmp == null)
                //    return false;

                val = tmp;
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }

        static public bool TryGetDateTimeOffset(JsonElement element, string propname, out DateTimeOffset val)
        {
            val = DateTimeOffset.MinValue;
            try
            {
                if(string.IsNullOrWhiteSpace(propname))
                    return false;

                // Get the property element...
                if(!element.TryGetProperty(propname, out var valEL))
                    return false;

                // Verify its type...
                if(valEL.ValueKind != JsonValueKind.Number)
                    return false;

                var tmp = valEL.GetInt64();
                //if(tmp == null)
                //    return false;

                // Convert it to a DateTimeOffset...
                val = DateTimeOffset.FromUnixTimeSeconds(tmp);

                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }
    }
}
