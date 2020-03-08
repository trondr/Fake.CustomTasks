namespace trondr.Fake.CustomTasks

module SignTool =
    
    open System.Runtime.CompilerServices
    [<assembly: InternalsVisibleTo("trondr.Fake.CustomTasks.Tests")>]
    do()

    open System.Text
    open System.Text.RegularExpressions
    open System.Diagnostics

    /// from http://stackoverflow.com/a/12364234/7913
    /// <summary>
    /// Encodes an argument for passing into a program
    /// </summary>
    /// <param name="original">The value that should be received by the program</param>
    /// <returns>The value which needs to be passed to the program for the original value 
    /// to come through</returns>
    let internal encodeParameterArgument original =
        let value = Regex.Replace(original, @"(\\*)" + "\"", @"$1\$0")
        let newValue = Regex.Replace(value, @"^(.*\s.*?)(\\*)$", "\"$1$2$2\"")
        newValue
        

    type SignResult = 
        |Success 
        |TimeServerError of string
        |Failed of string
        |Uknown

    let internal signToolExe =
        //Build list of search folders
        let programFilesFolders = 
            [
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFilesX86)
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles)
            ]        
        let searchFolders =
            programFilesFolders
            |> List.map(fun pf ->
                            [
                                System.IO.Path.Combine(pf,"Windows Kits")
                                System.IO.Path.Combine(pf,"Microsoft SDKs")
                            ]
                )
            |>List.concat
        //Find all signtool.exe's
        let signToolExes =
            searchFolders
            |>List.map (fun f -> 
                    let files = System.IO.Directory.GetFiles(f,"signtool.exe",System.IO.SearchOption.AllDirectories)
                    files                    
                    |>List.ofArray
                )
            |>List.concat
            |>List.sortDescending

        //Find latest signtool.exe
        let latestVersion file1 file2 =
            let file1Version = System.Diagnostics.FileVersionInfo.GetVersionInfo(file1)
            let file2Version = System.Diagnostics.FileVersionInfo.GetVersionInfo(file2)
            let version1 = new System.Version(file1Version.ProductVersion)
            let version2 = new System.Version(file2Version.ProductVersion)
            if (version1 > version2) then
                file1
            else
                file2

        let firstFound = signToolExes.[0]
        let signToolExe = 
            signToolExes
            |> List.fold latestVersion firstFound
        signToolExe

    
    let internal getSignToolArguments sha1Thumbprint description timeStampServer files =
        let signToolArguments = new StringBuilder()

        signToolArguments.Append("sign") |> ignore
        //Thumbprint        
        signToolArguments.Append(" /sha1 " + (encodeParameterArgument sha1Thumbprint)) |> ignore
        
        //Description
        match description with
        |Some d -> 
            signToolArguments.Append(" /d " + (encodeParameterArgument d)) |> ignore
        |None -> ()
        
        //Time server
        match timeStampServer with
        |Some ts ->
            signToolArguments.Append(" /t " + (encodeParameterArgument ts)) |> ignore
        |None -> ()
        
        //Files to be signed
        let encodedFileParameters =
            files
            |>Array.map(fun f-> encodeParameterArgument f)
        signToolArguments.Append(" " + System.String.Join(" ", encodedFileParameters )) |> ignore
        signToolArguments.ToString()

    let internal runSignToolUnsafe arguments =
        use signToolProcess = new System.Diagnostics.Process()
        let startInfo = new System.Diagnostics.ProcessStartInfo(signToolExe,arguments)
        startInfo.UseShellExecute <- false
        startInfo.CreateNoWindow <- true
        startInfo.WorkingDirectory <- System.IO.Directory.GetCurrentDirectory()
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        signToolProcess.StartInfo <- startInfo
        let outputs = System.Collections.Generic.List<string>()
        let errors = System.Collections.Generic.List<string>()
        let outputHandler f (_sender:obj) (args:DataReceivedEventArgs) = f args.Data        
        signToolProcess.OutputDataReceived.AddHandler(DataReceivedEventHandler (outputHandler outputs.Add))
        signToolProcess.ErrorDataReceived.AddHandler(DataReceivedEventHandler (outputHandler errors.Add))
        let started =
            try
                signToolProcess.Start()
            with
            | ex ->
                ex.Data.Add("signtool.exe",signToolExe)
                reraise()
        if not started then
            failwithf "Failed to start process %s" signToolExe        
        signToolProcess.BeginOutputReadLine()
        signToolProcess.BeginErrorReadLine()
        signToolProcess.WaitForExit()
        let listToString l = 
            l 
            |> Seq.filter (fun o -> System.String.IsNullOrEmpty o |> not)
            |> Seq.toArray
            |> String.concat System.Environment.NewLine
        match signToolProcess.ExitCode with
        |0 ->
            SignResult.Success
        |_ ->
            let errorMessages = listToString errors
            let isTimeServerError (errorMessage:string) =
                errorMessage.Contains("timestamp server") && errorMessage.Contains("could not be reached")
            match (isTimeServerError errorMessages) with
            |true -> SignResult.TimeServerError errorMessages
            |false -> SignResult.Failed errorMessages

    let private runSignTool' signToolArguments =
        try
            runSignToolUnsafe signToolArguments
        with
        | ex -> SignResult.Failed ex.Message

    let rec private signWithTimeServer sha1Thumbprint description timeStampServers files =           
        match timeStampServers with
        |[] -> 
            //No time server specified.
            let signtoolArguments = getSignToolArguments sha1Thumbprint description None files
            runSignTool' signtoolArguments
        |[ts] -> 
            let signtoolArguments = getSignToolArguments sha1Thumbprint description (Some ts) files
            runSignTool' signtoolArguments
        |ts::xs ->
            let signtoolArguments = getSignToolArguments sha1Thumbprint description (Some ts) files
            let signResult = runSignTool' signtoolArguments
            match signResult with
            |SignResult.Success -> signResult
            | _ ->
                signWithTimeServer sha1Thumbprint description xs files

    let runSignTool sha1Thumbprint description timeStampServers files =
        signWithTimeServer sha1Thumbprint description timeStampServers files
    