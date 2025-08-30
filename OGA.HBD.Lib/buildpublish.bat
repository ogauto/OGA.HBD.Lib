REM Host Bootstrap Document Library

REM Build the library...
dotnet restore "./OGA.HBD.Lib_NET5/OGA.HBD.Lib_NET5.csproj"
dotnet build "./OGA.HBD.Lib_NET5/OGA.HBD.Lib_NET5.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.HBD.Lib_NET5/OGA.HBD.Lib_NET5.csproj"
dotnet build "./OGA.HBD.Lib_NET5/OGA.HBD.Lib_NET5.csproj" -c DebugWin --runtime win --no-self-contained

dotnet restore "./OGA.HBD.Lib_NET6/OGA.HBD.Lib_NET6.csproj"
dotnet build "./OGA.HBD.Lib_NET6/OGA.HBD.Lib_NET6.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.HBD.Lib_NET6/OGA.HBD.Lib_NET6.csproj"
dotnet build "./OGA.HBD.Lib_NET6/OGA.HBD.Lib_NET6.csproj" -c DebugWin --runtime win --no-self-contained

dotnet restore "./OGA.HBD.Lib_NET7/OGA.HBD.Lib_NET7.csproj"
dotnet build "./OGA.HBD.Lib_NET7/OGA.HBD.Lib_NET7.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.HBD.Lib_NET7/OGA.HBD.Lib_NET7.csproj"
dotnet build "./OGA.HBD.Lib_NET7/OGA.HBD.Lib_NET7.csproj" -c DebugWin --runtime win --no-self-contained

REM Create the composite nuget package file from built libraries...
C:\Programs\nuget\nuget.exe pack ./OGA.HBD.Lib.nuspec -IncludeReferencedProjects -symbols -SymbolPackageFormat snupkg -OutputDirectory ./Publish -Verbosity detailed

REM To publish nuget package...
dotnet nuget push -s http://192.168.1.161:8080/v3/index.json ".\Publish\OGA.HBD.Lib.1.0.1.nupkg"
dotnet nuget push -s http://192.168.1.161:8080/v3/index.json ".\Publish\OGA.HBD.Lib.1.0.1.snupkg"

TIMEOUT 10

ECHO "DONE"
