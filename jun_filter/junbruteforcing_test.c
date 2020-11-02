/*
This is the Prototype(2) of bruteforce-fuzztesting automation code.
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


DWORD constraints[50] = {
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
        0xa3350448,
        0xa3350444,
        0xa3350450,
        0xa3350420,
        0xa3350040,
        0xa3350018,
        0xa335004c,
        0xa3350008,
        0xa3350020,
        0xa335000c,
        0xa3350000,
        0xa3350028,
        0xa3350048,
        0xa3350024,
        0xa335001c,
        0xa335002c,
        0xa3350034,
        0xa3350014,
        0xa3350038,
        0xa3350030,
        0xa3350050,
        0xa3350004,
        0xa3350044,
        0xa335003c,
        0xacd2201c,
        0xacd22018,
        0xacd22004,
        0xacd22020,
        0xacd22014,
        0xacd22010,
        0xacd22008,
        0xacd2200c,
        0xacd22024,
};

// decode_buf(==kAFL_decoded)는 ioctl code갯수만큼 있다. 각각의 버퍼에 분류한 ioctl-data 값 넣어주기 (decoder)
// data와 size는 fuzzer에서 받은 전체 패이로드 data랑 패이로드 size랍니다. 무조건 그걸 받아와요.
int32_t payload_decode(uint8_t* data, int32_t size, kAFL_IRP decoded_buf[]) 
{
    int32_t cIndex;
    int32_t ioctl_num = 0; // ioctl_num == decoded_len
    int last_index = size-1;
    int i = 0;
    //fuzzer한테 받아온 데이터 끝까지
    if ( data[0] == '0' || data[0] == '1' || data[0] == '5' || data[0] == '6' || data[0] == '7' || data[0] == '9'){
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
                    //다음 ioctl code 찾기!
                    int k = i+1;
                    while (k < size){
                        if (k == last_index){
                            if ( data[k] == '0' || data[k] == '1' || data[k] == '5' || data[k] == '6' || data[k] == '7' || data[k] == '9'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;
                                }
                                else{
                                    decoded_buf[ioctl_num].payload = &data[++i];
                                    break;
                                }
                            }

                            else{
                                decoded_buf[ioctl_num].inputBufferSize = k-i;
                                decoded_buf[ioctl_num].payload = &data[++i];
                                break;
                            }
                        }

                        else{
                            if ( data[k] == '0' || data[k] == '1' || data[k] == '5' || data[k] == '6' || data[k] == '7' || data[k] == '9'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;}
                                else{
                                    decoded_buf[ioctl_num].payload = &data[++i];
                                    break;
                                }
                            }
                        }
                        k++;
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
                    return ioctl_num;}
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[1] && decoded_buf[ioctl_count].inputBufferSize == 16){
                    return ioctl_num;}
                // ioctl_code [2] has no constraints!
                // ioctl_code [3] has no constraints!
                // ioctl_code [4] has no constraints!
                else if (decoded_buf[ioctl_count].ioctlCode == constraints[5] && decoded_buf[ioctl_count].inputBufferSize != 0){
                    return ioctl_num;}
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
    }
    else{
        return -1;
    }
    return -1;
}



int main(int argc, char** argv)
{
    kAFL_IRP decoded_buf[0x20];

    // uint8_t* outBuffer = NULL;

    hprintf("Starting... %s\n", argv[0]);
    
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);



    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\medcored",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("cannot get device handle: 0x%x\n", GetLastError());
        ExitProcess(0);
    }

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);
    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);




    while (1) {
        /* request new payload (blocking) */
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

        int32_t ioctl_num = payload_decode(payload_buffer->data, payload_buffer->size, decoded_buf);

        hprintf("Show me the ioctl_num : %ld", ioctl_num);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        if (ioctl_num != -1){
            // payload_buffer->data는 fuzzer에서 넘어온 전체 패이로드, payload_buffer->size는 fuzzer에서 넘어온 패이로드의 전체길이
            // hprintf("Here is decodedbuf %s, %ld\n", payload_buffer->data, payload_buffer->size);
            hprintf("Congraturation! you can pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);    


            for (int j = 0; j < ioctl_num; j++) {
                /* kernel fuzzing */
                // hprintf("Congraturation! you can pass this filter! ioctlCode : %x payload : %s inputbuffersize : %ld \n", decoded_buf[j].ioctlCode, decoded_buf[j].payload, decoded_buf[j].inputBufferSize);    
                DeviceIoControl(kafl_vuln_handle,
                    (DWORD)decoded_buf[j].ioctlCode,
                    (LPVOID)decoded_buf[j].payload,
                    (DWORD)decoded_buf[j].inputBufferSize,
                    NULL,
                    0,
                    NULL,
                    NULL
                );
            }
            /* inform fuzzer about finished fuzzing iteration */
            // hprintf("Injection finished.\n");
            
        }
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    return 0;
}