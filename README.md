# PEINFECTION

Chương trình chèn shellcode vào các file thực thi windows.
Các kỹ thuật:

- **Anti-VM**: Dùng cpuid với eax = 1
- **Anti-VM**: Kiểm tra Hypervisor brand với cpuid (eax = 0x40000000)
- **Anti-Debug**: Kiểm tra PEB.BeingDebugged

Chương trình sau khi chèn sẽ:

- Thực thi chương trình bình thường khi chạy ở máy ảo, hoặc debug.
- Hiện messagebox với nội dung: Infected by 17520444_17520293 sau đó chạy chương trình bình thường.
