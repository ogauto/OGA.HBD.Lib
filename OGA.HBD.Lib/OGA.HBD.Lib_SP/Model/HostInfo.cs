using OGA.HBD.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Holds the host/instance metadata portion of a Host Bootstrap Document.
    /// </summary>
    public class HostInfo
    {
        /// <summary>
        /// Name of the assigned region for the host/instance
        /// </summary>
        public string region { get; set; }

        /// <summary>
        /// Name of the assigned availability zone for the host/instance
        /// </summary>
        public string availZone { get; set; }

        /// <summary>
        /// Unique identifier of the host/instance
        /// </summary>
        public string instanceId { get; set; }

        /// <summary>
        /// Name of the assigned tenant that the host/instance belongs to
        /// </summary>
        public string tenant { get; set; }

        /// <summary>
        /// Name of the image the instance is based on.
        /// </summary>
        public string imageName { get; set; }

        /// <summary>
        /// When host/instance was created
        /// </summary>
        public long creationTime { get; set; }

        /// <summary>
        /// Id of the assigned cluster, that the host/instance participates in.
        /// </summary>
        public string clusterId { get; set; }

        /// <summary>
        /// Name of the assigned cluster, that the host/instance participates in.
        /// </summary>
        public string clusterName { get; set; }

        /// <summary>
        /// Assigned environment: dev, test, val, prod
        /// </summary>
        public string environment { get; set; }


        /// <summary>
        /// Public constructor, that baselines all values.
        /// </summary>
        public HostInfo()
        {
            this.region = string.Empty;
            this.availZone = string.Empty;
            this.instanceId = string.Empty;
            this.tenant = string.Empty;
            this.imageName = string.Empty;
            this.creationTime = 0;
            this.clusterId = string.Empty;
            this.clusterName = string.Empty;
            this.environment = string.Empty;
        }

        /// <summary>
        /// Copies from another instance.
        /// </summary>
        /// <param name="hi"></param>
        public void CopyFrom(HostInfo hi)
        {
            this.region = hi.region;
            this.availZone = hi.availZone;
            this.instanceId = hi.instanceId;
            this.tenant = hi.tenant;
            this.imageName = hi.imageName;
            this.creationTime = hi.creationTime;
            this.clusterId = hi.clusterId;
            this.clusterName = hi.clusterName;
            this.environment = hi.environment;
        }


        /// <summary>
        /// Public method for recovering a HostInfo instance from a JsonDocument.
        /// This is used when recovering data from a verified Host Bootstrap Document.
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        static public (int res, HostInfo? doc) RecoverHostInfo_fromPayload(JsonDocument payload)
        {
            try
            {
                // Check the payload instance...
                if (payload == null)
                {
                    return (-1, null);
                }

                // Extract the host info section of the bootstrap document...
                if(!payload.RootElement.TryGetProperty("hostInfo", out var hostinfo))
                {
                    return (-1, null);
                }

                // And, continue to retrieve properties from it...
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "region", out var region))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "availZone", out var availzone))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "instanceId", out var instanceid))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "tenant", out var tenant))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "imageName", out var imagename))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetLong(hostinfo, "creationTime", out var creationtime))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "clusterId", out var clusterid))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "clusterName", out var clustername))
                {
                    return (-1, null);
                }
                if(!JsonDocument_Helpers.TryGetString(hostinfo, "environment", out var env))
                {
                    return (-1, null);
                }

                var doc = new HostInfo();
                doc.availZone = availzone;
                doc.clusterId = clusterid;
                doc.clusterName = clustername;
                doc.creationTime = creationtime;
                doc.environment = env;
                doc.imageName = imagename;
                doc.instanceId = instanceid;
                doc.region = region;
                doc.tenant = tenant;

                return (1, doc);
            }
            catch(Exception e)
            {
                return (-10, null);
            }
        }
    }
}
