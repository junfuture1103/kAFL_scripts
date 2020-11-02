/*
Copyright (C) 2017 Robert Gawlik
This file is part of kAFL Fuzzer (kAFL).
QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.
QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>
#include <stdio.h>
#include "kafl_user.h"

#define IOCTL    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL2    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef enum { false, true } bool;

typedef struct _kAFL_IRP {
    DWORD ioctlCode;
    int32_t inputBufferSize;
    int32_t outputBufferSize;
    uint8_t* payload;
} kAFL_IRP;

DWORD constraints[3] = {
    IOCTL,
    IOCTL2,
};

int32_t payload_decode(uint8_t* data, int32_t size, kAFL_IRP decoded_buf[])
{
    int32_t cIndex;
    int32_t ioctl_num = 0;
    if (data[0] == '0' || data[0] == '1') {
        cIndex = data[0] - '0';
        decoded_buf[ioctl_num].ioctlCode = constraints[cIndex];
        decoded_buf[ioctl_num].payload = &data[1];
        decoded_buf[ioctl_num].inputBufferSize = size - 1;
        printf("[DECODED] ioctl_code : %lx, payload : %s, size : %d\n", decoded_buf[ioctl_num].ioctlCode, decoded_buf[ioctl_num].payload, decoded_buf[ioctl_num].inputBufferSize);
        ioctl_num += 1;
        return ioctl_num;
    }
    else {
        return -1;
    }
}


int main(int argc, char** argv)
{
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    //LPVOID payload_buffer = (LPVOID)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    kAFL_IRP decoded_buf[0x20];

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;

    hprintf("Here is CreateFile");
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\junToy",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        printf("[-] KAFL test: Cannot get device handle: 0x%lX\n", GetLastError());
        ExitProcess(0);
    }
    hprintf("SUBMIT_CR3");
    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
    hprintf("GET_PAYLOAD");
    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    while(1){
            hprintf("NEXTPAYLOAD");
            kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
            /* request new payload (*blocking*) */

            int32_t ioctl_num = payload_decode(payload_buffer->data, payload_buffer->size, decoded_buf);
            hprintf("Show me the ioctl_num : %ld", ioctl_num);
            
            if (ioctl_num == -1){
                hprintf("Shit. you can't pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);
                continue;
            }
            
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
            hprintf("Congraturation! you can pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);
            /* kernel fuzzing */
                hprintf("[SENDING DECODED PAYLOAD...] payload : %s inputbuffersize : %ld \n", decoded_buf[j].payload, decoded_buf[j].inputBufferSize);
                /* kernel fuzzing */
                DeviceIoControl(kafl_vuln_handle,
                    decoded_buf[0].ioctlCode,
                    (LPVOID)decoded_buf[0].payload,
                    (DWORD)decoded_buf[0].inputBufferSize,
                    NULL,
                    0,
                    NULL,
                    NULL
                );
            /* inform fuzzer about finished fuzzing iteration */
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
        }

    return 0;
}