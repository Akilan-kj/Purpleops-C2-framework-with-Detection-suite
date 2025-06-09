rule GitHub_C2_Agent {
    meta:
        description = "Detects GitHub-based C2 agent behavior"
        author = "Akilan"
    strings:
        $github_api = "https://api.github.com/repos/"
        $powershell_bypass = "powershell -exec bypass"
        $agent_registration = "Agent Registered:"
    condition:
        any of ($github_api, $powershell_bypass, $agent_registration)
}

rule PowerShell_Bypass_C2 {
    meta:
        description = "Detects PowerShell command execution with Bypass mode"
    strings:
        $powershell_exec = "powershell -NoProfile -ExecutionPolicy Bypass -Command"
    condition:
        $powershell_exec
}

rule UUID_Agent_Registration {
    meta:
        description = "Detects C2 agent registration using UUID"
    strings:
        $uuid_generation = "uuid.New().String()"
        $agent_registered = "Agent Registered: "
    condition:
        any of ($uuid_generation, $agent_registered)
}

rule GitHub_PAT_Detection {
    meta:
        description = "Detects hardcoded GitHub Personal Access Tokens (PAT)"
    strings:
        $github_pat = "github_pat_"
        $auth_header = "Authorization: token "
    condition:
        any of ($github_pat, $auth_header)
}

rule C2_Agent_Polling {
    meta:
        description = "Detects continuous polling behavior in C2 agent"
    strings:
        $polling_interval = "time.Sleep(5 * time.Second)"
        $http_request = "http.NewRequest(\"GET\","
    condition:
        all of ($polling_interval, $http_request)
}

rule Suspicious_PowerShell_Encoding {
    meta:
        description = "Detects PowerShell encoding and execution attempts"
    strings:
        $ps_encoding = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8"
        $ps_command = "powershell -NoProfile -ExecutionPolicy Bypass -Command"
    condition:
        all of ($ps_encoding, $ps_command)
}

rule HTTP_Command_Injection {
    meta:
        description = "Detects command injection through GitHub issue comments"
    strings:
        $comment_identifier = "Command: "
        $json_body = "json.Unmarshal(body, &comments)"
        $command_execution = "executeCommand(extractedCommand)"
    condition:
        all of ($comment_identifier, $json_body, $command_execution)
}

rule Go_Windows_Process_Manipulation {
    meta:
        description = "Detects Go programs using Windows API for process manipulation"
    strings:
        $create_job = "windows.CreateJobObject"
        $assign_process = "windows.AssignProcessToJobObject"
        $kill_on_close = "windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"
    condition:
        any of ($create_job, $assign_process, $kill_on_close)
}
