package main

import (
	"bytes"
	"fmt"
	"flag"
	"math"
	"sync"
	//"encoding/binary"
	"syscall"
	"os/signal"
	"os"
	"unsafe"
	"github.com/briandowns/spinner"
	"time"

	ps "github.com/mitchellh/go-ps"
)


const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
	MEM_COMMIT                = 0x1000
	PAGE_EXECUTE_READWRITE    = 0x40
	PAGE_READWRITE            = 0x04
	PAGE_READONLY             = 0x02
	PAGE_EXECUTE           = 0x10
)

var (
	modkernel32           = syscall.NewLazyDLL("kernel32.dll")
	procVirtualQueryEx    = modkernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")
	wg                    sync.WaitGroup
	mu                    sync.Mutex
)

// MEMORY_BASIC_INFORMATION structure
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// List of known syscall SSNs for detection
var knownSSNs = map[string]byte{
	//"NtCreateThreadEx":         0xC2,
	//"NtWriteVirtualMemory":     0x3A,
	//"NtAllocateVirtualMemory":  0x18,
	//"NtOpenProcess":            0x26,
	"NtFreeVirtualMemory":      0x1E,
	//"NtProtectVirtualMemory":   0x50,
}

var knownSyscallOpcodes = []byte{0x4C, 0x8B, 0xD1, 0xB8}

func isCurrentProcess(pid int) bool {
	return pid == os.Getpid()
}

var xorPatterns = []struct {
	pattern []byte
	mask    []byte
}{
	{[]byte{0x31, 0xC0, 0x48, 0x89, 0x00, 0x48, 0x83, 0x00}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00}},
	{[]byte{0x32, 0xC0, 0x83, 0xF8, 0x00, 0x89, 0x00}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00}},
	{[]byte{0x33, 0xC9, 0x48, 0x83, 0xC1}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
}

func isWindows(process ps.Process) bool{
	legitimateProcesses := map[string]bool{
		"services.exe": true,
		"svchost.exe": true,
		"lsass.exe": true,
		"wininit.exe": true,
		"winlogon.exe": true,
		"csrss.exe": true,
		"smss.exe": true,
		"dllhost.exe": true,
		"taskhostw.exe": true,
		"conhost.exe": true,
		"System": true,
		"SystemSettings.exe": true,
		"OneDrive.exe": true,
		"taskmgr.exe": true,
		"vmtoolsd.exe": true,
		"msedge.exe": true,
		"chrome.exe": true,
		"firefox.exe": true,
		"smartscreen.exe": true,
		"FileCoAuth.exe": true,
		"RuntimeBroker.exe": true,
		"ApplicationFrameHost.exe": true,
		"SearchApp.exe": true,
		"explore.exe": true,
		"explorer.exe": true,
		"sihost.exe": true,
		"WmiApSrv.exe": true,
		"PhoneExperienceHost.exe": true,
		"CalculatorApp.exe": true,
		"TextInputHost.exe": true,
		"StartMenuExperienceHost.exe": true,
		"ProcessHacker.exe": true,
	}
	if process.PPid() == 0 || legitimateProcesses[process.Executable()] {
		return true
	}
	return false
}

func matchPattern(data, pattern, mask []byte) bool {
	if len(data) < len(pattern) {
		return false
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := range pattern {
			if mask[j] == 0xFF && data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func scanBuffer(buffer []byte) bool {
	for _, p := range xorPatterns {
		if matchPattern(buffer, p.pattern, p.mask) {
			return true
		}
	}
	return false
}
// VirtualQueryEx wrapper
func VirtualQueryEx(hProcess syscall.Handle, lpAddress uintptr, lpBuffer unsafe.Pointer, dwLength uintptr) (int, error) {
	ret, _, err := procVirtualQueryEx.Call(uintptr(hProcess), lpAddress, uintptr(lpBuffer), dwLength)
	if ret == 0 {
		return 0, err
	}
	return int(ret), nil
}

// ReadProcessMemory wrapper
func ReadProcessMemory(hProcess syscall.Handle, lpBaseAddress uintptr, lpBuffer unsafe.Pointer, nSize uintptr, lpNumberOfBytesRead *uintptr) (bool, error) {
	ret, _, err := procReadProcessMemory.Call(uintptr(hProcess), lpBaseAddress, uintptr(lpBuffer), nSize, uintptr(unsafe.Pointer(lpNumberOfBytesRead)))
	if ret == 0 {
		return false, err
	}
	return true, nil
}

// Calculate Shannon entropy (used for SleepMask detection)
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	frequency := make(map[byte]float64)
	for _, b := range data {
		frequency[b]++
	}

	var entropy float64
	dataLen := float64(len(data))
	for _, count := range frequency {
		prob := count / dataLen
		entropy -= prob * math.Log2(prob)
	}
	return entropy
}

// Check for Cobalt Strike Beacon XOR-encoded configuration (common 4-byte XOR key)
func isBeaconConfig(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Common XOR keys (e.g., 0x2e, 0x2f, 0x69, 0x6e)
	xorKeys := [][]byte{{0x2e, 0x2f, 0x69, 0x6e}, {0x1e, 0x2d, 0x3c, 0x4b}}
	for _, key := range xorKeys {
		decrypted := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			decrypted[i] = data[i] ^ key[i%4]
		}

	}
	return false
}


var detectedPIDs = sync.Map{} // Map to track detected PIDs
// Function to detect Hell's Gate/Heaven's Gate technique
func detectHellShell(pid int,data []byte) bool {
	if p, err := ps.FindProcess(pid); err == nil && isWindows(p){
		return false
	}
	detected := false
	for _, ssn := range knownSSNs {
		stub := append([]byte{0x31, 0xC0, 0x48, 0x89}, ssn) // Match initialization like StartCall
		if bytes.Contains(data, stub) || bytes.Contains(data, []byte{0xFF, 0x25}) { // Detect jump to CallAddr
			if _, loaded := detectedPIDs.LoadOrStore(pid, true); !loaded {
				return true
				detected = true
			    break	
			}
						
		}
		if detected {
			break
		}
	}
	return false
}



// Detect modified or missing PE headers (UDRL detection)
func isSuspiciousPEHeader(data []byte) bool {
    //if len(data) < 64 { 
       // return true // Minimum PE header size is typically larger than 64 bytes
  //  }

    // Validate MZ header
   // if string(data[:2]) != "MZ" { 
     //   return true 
   // }

    // Extract PE header offset
    //peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
   // if peOffset < 0x40 || peOffset > uint32(len(data)-4) {
      //  return true // Offset is out of range
    //}

    // Validate PE signature
   // if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
   //     return true 
   // }

    // Additional checks for suspicious fields (optional)
    // Check for invalid machine type or sections
  //  machineType := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
   // if machineType != 0x14c && machineType != 0x8664 { // 0x14c = x86, 0x8664 = x64
   //     return true
   // }

   // numberOfSections := binary.LittleEndian.Uint16(data[peOffset+6 : peOffset+8])
   // if numberOfSections == 0 || numberOfSections > 96 { // Unrealistic section count
   //     return true
   // }

    return false
}

// Detect SleepMask by identifying high-entropy encrypted memory regions
func isEncryptedMemory(data []byte) bool {
	entropy := calculateEntropy(data)
	return entropy > 8.5 // High entropy suggests encryption
}

// Detect API redirection used in BeaconGate
func isBeaconGateRedirected(data []byte) bool {
	suspiciousAPIs := [][]byte{
		//[]byte("VirtualAlloc"),
		[]byte("CreateThread"),
		[]byte("InternetConnectA"),
		//[]byte("LoadLibrary"),
		//[]byte("GetProcAddress"),
	}
	for _, api := range suspiciousAPIs {
		if bytes.Contains(data, api) {
			return true
		}
	}
	return false
}

// Detect manual import resolution (UDRL indicator)
func isManualImportResolution(data []byte) bool {
	return bytes.Contains(data, []byte("ResolveImports"))// ||
		//bytes.Contains(data, []byte("LoadLibraryA")) ||
		//bytes.Contains(data, []byte("GetProcAddress"))
}

// Detect relocation handling (UDRL indicator)
func isRelocationHandling(data []byte) bool {
	return bytes.Contains(data, []byte("ProcessRelocations"))
}


// Scan memory for Beacon techniques
func scanForBeacon(pid int, data []byte, addr uintptr, handle syscall.Handle) {
	if isCurrentProcess(pid) {
		return // Skip scanning the current process
	}
	suspiciousPE := isSuspiciousPEHeader(data)
	encryptedMemory := isEncryptedMemory(data)
	apiRedirection := isBeaconGateRedirected(data)
	manualImport := isManualImportResolution(data)
	relocationHandling := isRelocationHandling(data)
	reBeaconConfig := isBeaconConfig(data)
	rescanBuffer := scanBuffer(data)
	redetectHellShell := detectHellShell(pid, data)

	if reBeaconConfig || encryptedMemory || apiRedirection || manualImport || relocationHandling || suspiciousPE || redetectHellShell {
		mu.Lock()
		fmt.Printf("[!] Suspicious activity detected in PID %d at address 0x%x It Maybe:\n", pid, addr)
		
		if encryptedMemory {
			fmt.Println("    - SleepMask Detected: High entropy in memory")
		}
		if suspiciousPE {
			fmt.Println("    - UDRL Detected: Modified or missing PE header")
		}
		if apiRedirection {
			fmt.Println("    - BeaconGate Detected: API call proxying found")
		}
		if manualImport {
			fmt.Println("    - UDRL Detected: Manual import resolution observed")
		}
		if relocationHandling {
			fmt.Println("    - UDRL Detected: Manual relocation processing detected")
		}
		if reBeaconConfig {
			fmt.Println("    - Beacon configuration: Beacon XOR-encoded configuration Detected")
		}
		if rescanBuffer {
			fmt.Println("    - Masked Beacon Detected: Beacon XOR-encoded Mask Detected")
		}
		if redetectHellShell {
			fmt.Println("    - Suspicious syscall detected: Hell's Gate/Heaven's Gate detected")
		}
		mu.Unlock()
	}
}

// Scan a process's memory
func scanProcessMemory(process ps.Process) {
	defer wg.Done()

	pid := process.Pid()
	handle, err := syscall.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(handle)
	var addr uintptr
	var memInfo MEMORY_BASIC_INFORMATION

	for {
		bytesReturned, err := VirtualQueryEx(handle, addr, unsafe.Pointer(&memInfo), unsafe.Sizeof(memInfo))
		if err != nil || memInfo.RegionSize == 0 || bytesReturned == 0 {
			break
		}

		if memInfo.State == MEM_COMMIT && (memInfo.Protect == PAGE_EXECUTE_READWRITE || memInfo.Protect == PAGE_READWRITE) {
			buffer := make([]byte, memInfo.RegionSize)
			var bytesRead uintptr
			success, err := ReadProcessMemory(handle, addr, unsafe.Pointer(&buffer[0]), uintptr(len(buffer)), &bytesRead)
			if err == nil && success {
				scanForBeacon(pid, buffer[:bytesRead], addr, handle)
			}
		}
		addr += memInfo.RegionSize
	}
}
func printBanner() {
    fmt.Println("############################################")
    fmt.Println("#            (\\(\\                          #")
    fmt.Println("#            ( -.-)                        #")
    fmt.Println("#           o((\")(\")                       #")
    fmt.Println("#                                          #")
    fmt.Println("#         C O B A L T S E N T R Y          #")
    fmt.Println("#  Cobalt Strike & Hell's Gate Scanner     #")
    fmt.Println("#     Created by Mohamed Alzhrani (0xmaz)  #")
    fmt.Println("############################################")
}

func startLoading() {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Prefix = "Scanning in progress... \n"
	s.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Println("\nPress 'q' then Enter to stop scanning...")
		var input string
		for {
			fmt.Scanln(&input)
			if input == "q" {
				s.Stop()
				fmt.Println("\n[+] Scanning stopped by user.")
				os.Exit(0)
			}
		}
	}()

	<-c // Wait for termination signal
	s.Stop()
	fmt.Println("\n[+] Scanning terminated.")
	os.Exit(0)
}

func main() {
	printBanner()

	scanAll := flag.Bool("all", false, "Scan all processes")
	pid := flag.Int("pid", 0, "Scan a single process by PID")
	flag.Parse()

	if *scanAll {
		processes, err := ps.Processes()
		if err != nil {
			fmt.Printf("Failed to list processes: %v\n", err)
			return
		}
		for _, process := range processes {
			wg.Add(1)
			go scanProcessMemory(process)
		}
	} else if *pid > 0 {
		process, err := ps.FindProcess(*pid)
		if err != nil || process == nil {
			fmt.Printf("Failed to find process with PID %d\n", *pid)
			return
		}
		wg.Add(1)
		go scanProcessMemory(process)
	} else {
		fmt.Println("Usage: ")
		flag.PrintDefaults()
		return
	}
	go startLoading()
	wg.Wait()
}
