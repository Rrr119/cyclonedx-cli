// This file is part of CycloneDX CLI Tool
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.
using System.Collections.Generic;

namespace CycloneDX.Cli.Models
{
    internal class SemanticDiffResult
    {
        public ComponentChanges Components { get; set; } = new ComponentChanges();
        public List<ComponentVersionChange> Versions { get; set; } = new List<ComponentVersionChange>();
        public DependencyChanges Dependencies { get; set; } = new DependencyChanges();
        public List<NoiseChange> Noise { get; set; } = new List<NoiseChange>();

        public bool HasChanges
        {
            get
            {
                return Components.Added.Count > 0
                    || Components.Removed.Count > 0
                    || Versions.Count > 0
                    || Dependencies.Added.Count > 0
                    || Dependencies.Removed.Count > 0;
            }
        }

        public bool HasNoise => Noise.Count > 0;

        public int NoiseCount => Noise.Count;

        public int RealChangeCount
        {
            get
            {
                return Components.Added.Count
                    + Components.Removed.Count
                    + Versions.Count
                    + Dependencies.Added.Count
                    + Dependencies.Removed.Count;
            }
        }
    }

    internal class ComponentChanges
    {
        public List<ComponentSnapshot> Added { get; set; } = new List<ComponentSnapshot>();
        public List<ComponentSnapshot> Removed { get; set; } = new List<ComponentSnapshot>();
    }

    internal class ComponentSnapshot
    {
        public string Type { get; set; }
        public string Group { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string Purl { get; set; }
        public string BomRef { get; set; }

        public string DisplayName
        {
            get
            {
                var groupPrefix = string.IsNullOrEmpty(Group) ? string.Empty : Group + "/";
                var versionSuffix = string.IsNullOrEmpty(Version) ? string.Empty : " @ " + Version;
                return groupPrefix + Name + versionSuffix;
            }
        }
    }

    internal class ComponentVersionChange
    {
        public string Type { get; set; }
        public string Group { get; set; }
        public string Name { get; set; }
        public string Purl { get; set; }
        public string FromVersion { get; set; }
        public string ToVersion { get; set; }

        public string DisplayName
        {
            get
            {
                var groupPrefix = string.IsNullOrEmpty(Group) ? string.Empty : Group + "/";
                return groupPrefix + Name;
            }
        }
    }

    internal class DependencyChanges
    {
        public List<DependencyEdgeChange> Added { get; set; } = new List<DependencyEdgeChange>();
        public List<DependencyEdgeChange> Removed { get; set; } = new List<DependencyEdgeChange>();
    }

    internal class DependencyEdgeChange
    {
        public DependencyEndpoint From { get; set; }
        public DependencyEndpoint To { get; set; }

        public string DisplayValue => From.DisplayName + " -> " + To.DisplayName;
    }

    internal class DependencyEndpoint
    {
        public string Group { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string Purl { get; set; }
        public string Ref { get; set; }

        public string DisplayName
        {
            get
            {
                if (!string.IsNullOrEmpty(Name))
                {
                    var groupPrefix = string.IsNullOrEmpty(Group) ? string.Empty : Group + "/";
                    var versionSuffix = string.IsNullOrEmpty(Version) ? string.Empty : " @ " + Version;
                    return groupPrefix + Name + versionSuffix;
                }

                return Ref;
            }
        }
    }

    internal class NoiseChange
    {
        public bool IsNoise { get; set; } = true;
        public string Category { get; set; }
        public string ChangeType { get; set; }
        public string Name { get; set; }
        public string From { get; set; }
        public string To { get; set; }

        public string DisplayValue
        {
            get
            {
                var namePrefix = string.IsNullOrEmpty(Name) ? string.Empty : " (" + Name + ")";
                return Category + namePrefix + ": " + (From ?? "(none)") + " -> " + (To ?? "(none)");
            }
        }
    }
}
