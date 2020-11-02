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
#define IOCTL2    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)
#define PAYLOAD_SIZE						(128 << 10)	

typedef enum { false, true } bool;

typedef struct _kAFL_IRP {
    DWORD ioctlCode;
    int32_t inputBufferSize;
    int32_t outputBufferSize;
    uint8_t* payload;
} kAFL_IRP;

// for non-fuzzing driver test
// typedef struct {
//     int32_t inputBufferlength;
//     uint8_t data[PAYLOAD_SIZE - sizeof(int32_t) - sizeof(uint8_t)];
// } kAFL_payload;

DWORD constraints[2] = {
    IOCTL,
    IOCTL2
};

// decode_buf(==kAFL_decoded)는 ioctl code갯수만큼 있다. 각각의 버퍼에 분류한 ioctl-data 값 넣어주기 (decoder)
// data와 size는 fuzzer에서 받은 전체 패이로드 data랑 패이로드 size랍니다. 무조건 그걸 받아와요.
int32_t payload_decode(uint8_t* data, int32_t size, kAFL_IRP decoded_buf[])
{
    int32_t cIndex;
    int32_t ioctl_num = 0; // ioctl_num == decoded_len
    // int last_index = size - 1;
    int i = 0;
    //fuzzer한테 받아온 데이터 끝까지
    if (data[0] == '0' || data[0] == '1') {
        cIndex = data[0] - '0';
        decoded_buf[ioctl_num].ioctlCode = constraints[cIndex];
        decoded_buf[ioctl_num].payload = &data[++i];
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
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\juntoy",
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

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    while(1){
            kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
            /* request new payload (*blocking*) */

            int32_t ioctl_num = payload_decode(payload_buffer->data, payload_buffer->size, decoded_buf);
            hprintf("Show me the ioctl_num : %ld", ioctl_num);
            
            if (ioctl_num == -1){
                hprintf("Shit. you can't pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);
                continue;
            }else{
                
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
            hprintf("Congraturation! you can pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);
            /* kernel fuzzing */
            for (int j = 0; j < ioctl_num; j++) {
                hprintf("[SENDING DECODED PAYLOAD...] payload : %s inputbuffersize : %ld \n", decoded_buf[j].payload, decoded_buf[j].inputBufferSize);
                /* kernel fuzzing */
                DeviceIoControl(kafl_vuln_handle,
                    decoded_buf[j].ioctlCode,
                    (LPVOID)decoded_buf[j].payload,
                    (DWORD)decoded_buf[j].inputBufferSize,
                    NULL,
                    0,
                    NULL,
                    NULL
                );
            }
            /* inform fuzzer about finished fuzzing iteration */
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
            }
    }

    return 0;
}