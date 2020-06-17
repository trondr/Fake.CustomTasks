namespace trondr.Fake.CustomTasks.Tests

open NUnit.Framework
open System
open System.IO
open trondr.Fake.CustomTasks.SignTool
open System.Reflection

[<TestFixture>]
module SignToolTests =
    
    [<Test>]
    let signToolExeTest () =
        
        let signToolExePath = trondr.Fake.CustomTasks.SignTool.getSignToolExe().Path
        printfn "Signtool.exe: %s" signToolExePath
        Assert.IsTrue(File.Exists(signToolExePath))
      
    [<Test>]
    let runSignToolTest_Success () =
        let sha1Thumbprint = System.Environment.GetEnvironmentVariable("CODE_SIGNING_SHA1_THUMBPRINT")
        let testDllFile = new FileInfo(Assembly.GetExecutingAssembly().Location)
        let temptestDllFile = new FileInfo(Path.Combine(Path.GetTempPath(),testDllFile.Name))
        File.Copy(testDllFile.FullName,temptestDllFile.FullName,true)
        let files = [|temptestDllFile.FullName|]
        let signResult = runSignTool sha1Thumbprint (Some "Some description") ["http://timestamp.verisign.com/scripts/timestamp.dll"] files
        Assert.AreEqual(signResult,SignResult.Success)

    [<Test>]
    let runSignToolTest_Fail () =
        let sha1Thumbprint = System.Environment.GetEnvironmentVariable("CODE_SIGNING_SHA1_THUMBPRINT")
        let files = [||]
        let signResult = runSignTool sha1Thumbprint (Some "Some description") ["http://timestamp.verisign.com/scripts/timestamp.dll"] files
        Assert.AreNotEqual(signResult,SignResult.Success)

    [<Test>]
    [<TestCase(@"C:\Program Files (x86)\Microsoft SDKs\ClickOnce\SignTool\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\arm64\signtool.exe",MachineType.Arm64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\arm64\signtool.exe",MachineType.Arm64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\arm64\signtool.exe",MachineType.Arm64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\arm64\signtool.exe",MachineType.Arm64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\arm64\signtool.exe",MachineType.Arm64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\8.0\bin\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\8.0\bin\x86\signtool.exe",MachineType.x86)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\8.1\bin\arm\signtool.exe",MachineType.Arm32)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\8.1\bin\x64\signtool.exe",MachineType.x64)>]
    [<TestCase(@"C:\Program Files (x86)\Windows Kits\8.1\bin\x86\signtool.exe",MachineType.x86)>]
    let ``getMachineType Tests`` (fileName:string,expectedMachineType:MachineType) =
        let actual = getMachineTypeFromFile fileName
        Assert.AreEqual(actual,expectedMachineType,"Machine type not expected.")        