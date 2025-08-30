# OGA.HBD.Lib
Library for Managing Host Bootstrap Documents

## Description
This library provides classes to create and verify Host Bootstrap Documents (similar to an AWS IID).\
It was created to have an agnostic method for indicating and attesting a host/instance's cluster, environment, and other metadata.\
This library is used by:
* Host Control Services, to retrieve their local host metadata.
* VM Provisioning, to generate HBDs for host/VM instances.

## Installation
OGA.HBD.Lib is available via private NuGet:
* NuGet Official Releases: [![NuGet](https://buildtools.ogsofttech.com:8079/packages/oga.hbd.lib)](https://buildtools.ogsofttech.com:8079/packages/oga.hbd.lib)

## Dependencies
This library depends on:
* [Microsoft.IdentityModel.JsonWebTokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
* [Microsoft.IdentityModel.Tokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
* [jose-jwt](https://github.com/dvsekhvalnov/jose-jwt)

## Building OGA.HBD.Lib
This library is built with the new SDK-style projects.
It contains multiple projects, one for each of the following frameworks:
* NET 5
* NET 6
* NET 7

And, the output nuget package includes runtimes targets for:
* linux-any
* win-any

## Framework and Runtime Support
Currently, the nuget package of this library supports the framework versions and runtimes of applications that I maintain (see above).
If someone needs others (older or newer), let me know, and I'll add them to the build script.

## Visual Studio
This library is currently built using Visual Studio 2022 17.6.3.

## License
Please see the [License](LICENSE).
