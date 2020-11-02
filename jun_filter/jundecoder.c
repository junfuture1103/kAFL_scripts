/*
This is the Prototype of bruteforce-fuzztesting automation code.
Designed for medcored.sys.
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "kafl_user.h"

typedef enum {false, true} bool;

typedef struct _kAFL_IRP {
    DWORD ioctlCode;
    int32_t inputBufferSize;
    int32_t outputBufferSize;
    uint8_t* payload;
} kAFL_IRP;


DWORD constraints[10] = {
        0xa3350404,
        0xa3350408,
        0xa335040c,
        0xa3350410,
        0xa3350424,
        0xa335041c,
        0xa3350414,
        0xa335044c,
        0xa3350418,
        0xa3350440,
};

int32_t decode_payload(uint8_t* data, int32_t size, kAFL_IRP decoded_buf[]) 
{
    int32_t cIndex;
    int32_t ioctl_num = 0; // ioctl_num == decoded_len
    int last_index = size-1;
    int i = 0;
    //fuzzer한테 받아온 데이터 끝까지
        while (i < size) {
            if ( data[i] == '0' || data[i] == '1' || data[i] == '5' || data[i] == '6' || data[i] == '7' || data[i] == '9'){
                cIndex = data[i] - '0';
                //0,1,2...값에서 진짜 ioctl 코드로 담아주기
                decoded_buf[ioctl_num].ioctlCode = constraints[cIndex];

                if (i == last_index){
                    decoded_buf[ioctl_num].inputBufferSize = 0 ;
                    decoded_buf[ioctl_num].payload = NULL;
                    return ioctl_num;
                }

                else{
                    int k = i+1;
                    //i번째 ioctl code에 해당하는 데이터 길이 찾기
                    while (k < size){
                        //탐색중에 마지막 인덱스에 도달했다면, 무조건 data값이 정해지기 때문에! k++해줄 필요 없음.
                        if (k == last_index){
                            //근데 그 아이가 ioctl_code라면?
                            if ( data[k] == '0' || data[k] == '1' || data[k] == '2' || data[k] == '3' || data[k] == '4' || data[k] == '5' || data[k] == '6' || data[k] == '7' || data[k] == '8' || data[k] == '9'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                //ioctl_code 다음에 바로 ioctl_code 나온경우
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;
                                }
                                //일반적인 경우
                                else{
                                    decoded_buf[ioctl_num].payload = &data[i+1];
                                    break;
                                }
                            }

                            //ioctl_code가 아니라면! 마지막이라 끝났다!
                            else{
                                decoded_buf[ioctl_num].inputBufferSize = k-i;
                                decoded_buf[ioctl_num].payload = &data[i+1];
                                break;
                            }
                        }

                        //그게 아니라면! 일반적인 경우 만약에 ioctl code못찾았으면 k++ 해줘야함.
                        else{
                            //ioctl_code에 해당하는애 발견하면은!
                            if ( data[k] == '0' || data[k] == '1' || data[k] == '2' || data[k] == '3' || data[k] == '4' || data[k] == '5'|| data[k] == '6' || data[k] == '7' || data[k] == '8' || data[k] == '9'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                //바로 다음에 또다른 ioctl_code가 나온다면!
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;}
                                //그거 아니고 일반적인 경우
                                else{
                                    decoded_buf[ioctl_num].payload = &data[i+1];
                                    break;
                                }
                            }
                            else{
                                k++;
                            }
                        }
                    }
                }

                //decoded_buf[ioctl_num].outputBufferSize = constraints[cIndex];
                i += decoded_buf[ioctl_num].inputBufferSize + 1;
                ioctl_num++;

            }else{
                i++;
            }
        }

        int ioctl_count = 0;
        while (ioctl_count < ioctl_num){
                if (decoded_buf[ioctl_count].ioctlCode == constraints[0] && decoded_buf[ioctl_count].inputBufferSize == 16){
                    return ioctl_num;
                }
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[1] && decoded_buf[ioctl_count].inputBufferSize == 16){
                    return ioctl_num;
                }
                // ioctl_code [2] has no constraints!
                // ioctl_code [3] has no constraints!
                // ioctl_code [4] has no constraints!
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[5] && decoded_buf[ioctl_count].inputBufferSize != 0){
                    return ioctl_num;
                }
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[6] && decoded_buf[ioctl_count].inputBufferSize != 0){
                    return ioctl_num;}
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[7] && decoded_buf[ioctl_count].inputBufferSize == 4){
                    return ioctl_num;}
                // ioctl_code [8] has no constraints!
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[9] && decoded_buf[ioctl_count].inputBufferSize == 1560){
                    return ioctl_num;}
                else{
                    return -1;
                }
                ioctl_count++;
            }
    return -1;
}

int main(int argc, char** argv)
{
    kAFL_IRP decoded_buf[0x20];
    uint8_t *outBuffer = NULL;
    char buf[0x100];

    hprintf("Starting... %s\n", argv[0]);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    hprintf("Attempting to open vulnerable device file (%s)\n", "\\\\.\\medcored");
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\medcored",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("[-] Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0); 
    }

    hprintf("Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    hprintf("Memset kAFL_payload at address %lx (size %d)\n", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    /* submit the guest virtual address of the payload buffer */
    hprintf("Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */
    hprintf("Submitting current CR3 value to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    while (1) {
        /* request new payload (blocking) */
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, (const char *)payload_buffer->data, payload_buffer->size);
        for (int i = 0; i < payload_buffer->size; i++) {
            if (buf[i] <= 0x20 || 0x7f <= buf[i]) {
                buf[i] = '.';
            }
        }
        hprintf("origianl payload: %s, original size: %d\n", buf, payload_buffer->size);

        int32_t decoded_len = decode_payload(payload_buffer->data, payload_buffer->size, decoded_buf);
        if (decoded_len == -1)
            continue;

        for (int i = 0; i < decoded_len; i++) {
            memset(buf, 0x00, sizeof(buf));
            memcpy(buf, (const char *)decoded_buf[i].payload, decoded_buf[i].inputBufferSize);
            for (int j = 0; j < decoded_buf[i].inputBufferSize; j++) {
                if (buf[j] <= 0x20 || 0x7f <= buf[j]) {
                    buf[j] = '.';
                }
        }

            /* kernel fuzzing */
            hprintf("Injecting data... (payload: %s, size: %d)\n", buf, decoded_buf[i].inputBufferSize);
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
            /* kernel fuzzing */
            DeviceIoControl(kafl_vuln_handle,
                decoded_buf[i].ioctlCode,
                (LPVOID)decoded_buf[i].payload,
                (DWORD)decoded_buf[i].inputBufferSize,
                (LPVOID)outBuffer,
                (DWORD)decoded_buf[i].outputBufferSize,
                NULL,
                NULL
            );
        }
        
        /* inform fuzzer about finished fuzzing iteration */
        hprintf("Injection finished.\n");
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    return 0;
}