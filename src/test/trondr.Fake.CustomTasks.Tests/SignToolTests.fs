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
        
        let signToolExePath = trondr.Fake.CustomTasks.SignTool.signToolExe
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
