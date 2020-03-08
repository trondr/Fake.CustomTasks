namespace trondr.Fake.CustomTasks.Tests

open NUnit.Framework

[<TestFixture>]
module Say =
    
    [<Test>]
    let hello name =
        printfn "Hello %s" name
        Assert.Inconclusive()
