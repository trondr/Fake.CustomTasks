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

    open System.IO
    open System

    type MachineType= 
        |Native = 0us
        |x86 = 0x014cus
        |Itanium = 0x0200us
        |x64 = 0x8664us
        |Arm32 = 0x1c4us
        |Arm64 = 0xaa64us

    //Source: https://stackoverflow.com/questions/197951/how-can-i-determine-for-which-platform-an-executable-is-compiled
    let getMachineTypeFromFile fileName =
        let pe_pointer_offset = 60
        let machine_offset = 4
        let bufferSize = 4096
        let mutable data:byte[] = Array.zeroCreate 4096
        use s = new System.IO.FileStream(fileName,FileMode.Open,FileAccess.Read)
        let bytesRead = s.Read(data,0,bufferSize)
        // dos header is 64 bytes, last element, long (4 bytes) is the address of the PE heade
        let pe_header_address = BitConverter.ToInt32(data, pe_pointer_offset)
        let machineUint = BitConverter.ToUInt16(data,pe_header_address+machine_offset)        
        let machineType = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint16, MachineType>(machineUint)
        machineType

    let getMachineTypeFromOperatingSystem () =
        let is64BitOs = System.Environment.Is64BitOperatingSystem
        match is64BitOs with
        |true -> MachineType.x64
        |false -> MachineType.x86

    type ExeInfo =
        {
            Path : string
            MachineType: MachineType
            Version: Version
        }

    let internal getSignToolExe () =
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
        //Find all signtool.exe's and get machinetype and version for each instance found
        let signToolExes =
            searchFolders
            |>List.map (fun f -> 
                    let files = System.IO.Directory.GetFiles(f,"signtool.exe",System.IO.SearchOption.AllDirectories)
                    files                    
                    |>List.ofArray
                )            
            |>List.concat
            |>List.map(fun f -> 
                    let machineType = getMachineTypeFromFile(f)
                    let fileVersionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(f)
                    let exeInfo =
                        {
                            Path = f
                            MachineType = machineType
                            Version = new System.Version(fileVersionInfo.ProductVersion)
                        }
                    exeInfo
                )            

        //Find latest signtool.exe
        let latestVersion exeFile1 exeFile2 =
            if (exeFile1.Version > exeFile2.Version) then
                exeFile1
            else
                exeFile2

        let firstFound = signToolExes.[0]
        let osMachineType = getMachineTypeFromOperatingSystem()
        let signToolExe = 
            signToolExes
            |> List.filter (fun f -> f.MachineType = osMachineType)
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
        let signToolExe = getSignToolExe()
        printfn "Running: \"%s\" %s" signToolExe.Path arguments
        let startInfo = new System.Diagnostics.ProcessStartInfo(signToolExe.Path, arguments)
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
            failwithf "Failed to start process %s" signToolExe.Path        
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
    