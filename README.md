# PEINFECTION

## Giới thiệu

Chương trình chèn shellcode vào các file thực thi windows.
Các kỹ thuật:

- **Anti-VM**: Dùng cpuid với eax = 1
- **Anti-VM**: Kiểm tra Hypervisor brand với cpuid (eax = 0x40000000)
- **Anti-Debug**: Kiểm tra PEB.BeingDebugged

Chương trình sau khi chèn sẽ:

- Thực thi chương trình bình thường khi chạy ở máy ảo, hoặc debug.
- Môi trường máy thật thì hiện messagebox với nội dung: Infected by 17520444_17520293 sau đó chạy chương trình bình thường.

## Môi trường

```
Python 3.6.5
```

Thư viện liên quan

```
- pefile
- tkinter
```

## Sử dụng

Clone project về

```sh
git clone https://github.com/h40huynh/peinfection.git
```

Chạy file app.py với python

```
cd peinfection
py app.py
```
